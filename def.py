class Firewall(OpenFlowController):
	"""
	This class implements an SDN controller which acts as a firewall.
	"""

	__metaclass__ = utils.Singleton

	CONFIG_FILE_PATH = 'config.yaml'
	EVENTS_FILE = 'events.bin'

	def __init__(self):
		self._incoming_port = None
		self._outgoing_port = None
		self._mode = None
		self._flow_active_time_secs = None
		self._time_to_keep_stats_secs = None
		self._firewall_dpid = None
		self._blacklist_rules = None
		self._whitelist_rules = None
		self._active_flows = []
		self._total_bandwidth = {}  # time -> bandwidth (Mbit/sec)
		self._load_configuration()
		self._events = self._load_events()
		super(Firewall, self).__init__()
		self._log.info('Firewall started, initial mode: %s' % self._mode.name)

	def set_mode(self, new_mode):
		"""
		Sets a new firewall working mode.
		"""

		self._log.info('Mode changed to: %s' % new_mode.name)
		self._mode = new_mode
		self._dump_configuration()
		self._remove_all_flow_records()

	def _remove_all_flow_records(self):
		"""
		Removes all active flow records from the controlled SDN switch.
		"""

		self._log.info('Removing all active flow records')
		if self._firewall_dpid in self._switches:
			self._switches[self._firewall_dpid].remove_flow_mod()

	def add_rule(self, rule):
		"""
		Adds a new firewall rule to the active rules set.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			self._log.info('Adding new rule to the blacklist rules set: %s' % rule)
			self._blacklist_rules.append(rule)

		if self._mode == Mode.WhiteList:
			self._log.info('Adding new rule to the whitelist rules set: %s' % rule)
			self._whitelist_rules.append(rule)

		self._dump_configuration()
		self._remove_all_flow_records()

	def remove_rule(self, rule_number):
		"""
		Removes a firewall rule from the active rules set.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			rule = self._blacklist_rules.pop(rule_number)
			self._log.info('Removing rule from the blacklist rules set: %s' % rule)

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			rule = self._whitelist_rules.pop(rule_number)
			self._log.info('Removing rule from the whitelist rules set: %s' % rule)

		self._dump_configuration()
		self._remove_all_flow_records()
		return rule

	def edit_rule(self, rule_number, rule):
		"""
		Edits an exiting firewall rule.
		"""

		if self._mode == Mode.PassThrough:
			raise ValueError("Can't edit rules while in passthrough mode")

		if self._mode == Mode.BlackList:
			if len(self._blacklist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			old_rule = self._blacklist_rules.pop(rule_number)
			self._blacklist_rules.append(rule)
			self._log.info('Replaced rule from the blacklist rules set: \n old: %s\n new: %s' % (old_rule, rule))

		if self._mode == Mode.WhiteList:
			if len(self._whitelist_rules) - 1 < rule_number:
				raise ValueError('Rule not found in rules list')
			old_rule = self._whitelist_rules.pop(rule_number)
			self._whitelist_rules.append(rule)
			self._log.info('Replaced rule from the whitelist rules set: \n old: %s\n new: %s' % (old_rule, rule))

		self._dump_configuration()
		self._remove_all_flow_records()
		return old_rule
