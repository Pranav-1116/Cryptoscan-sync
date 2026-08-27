"""Condition evaluators for policy rules.

Modules:
- algorithm_in_list: ALGORITHM_IN_LIST condition
- algorithm_mode_whitelist: ALGORITHM_MODE_WHITELIST condition
- base_condition: Abstract base class for all policy condition evaluators
- boolean_flag: BOOLEAN_FLAG condition
- complex_condition: COMPLEX policy condition — scoped multi-clause evaluation
- condition_factory: ConditionFactory — creates the correct condition evaluator
- key_size_minimum: KEY_SIZE_MINIMUM condition
- purpose_condition: PURPOSE_IN_LIST — apply a rule only when the finding purpose matches
- timeline_condition: TIMELINE policy condition — date-gated algorithm retirement
"""
