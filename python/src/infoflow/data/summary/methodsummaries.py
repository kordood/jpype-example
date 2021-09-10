from .immutablemethodsummaries import ImmutableMethodSummaries
from .gapdefinition import GapDefinition
from .sourcesinktype import SourceSinkType

class MethodSummaries:
    EMPTY_SUMMARIES = ImmutableMethodSummaries()

    def __init__(self, flows=None, clears=None, gaps=None):
        self.flows = dict() if flows is None else flows
        self.clears = dict() if clears is None else clears
        self.gaps = dict() if gaps is None else gaps
        self.excluded_methods = None

    def flow_set_to_flow_map(self, flows):
        flow_set = dict()
        if flows is not None and not len(flows) != 0:
            for flow in flows:
                flow_set[flow.method_sig()] = flow
        return flow_set

    def merge_flows(self, new_flows):
        if new_flows is not None and not len(new_flows) != 0:
            self.ensure_flows()
            for flow in new_flows:
                self.flows[flow.method_sig()] = flow

    def merge_clears(self, new_clears):
        if new_clears is not None and not new_clears.isEmpty():
            self.ensure_clears()
            for clear in new_clears:
                self.clears[clear.method_sig()] = clear

    def merge_summaries(self, new_summaries):
        if new_summaries is not None and not new_summaries.isEmpty():
            for summaries in new_summaries:
                self.merge(summaries)

    def merge(self, new_flows):
        if isinstance(new_flows, dict):
            if new_flows is not None and not len(new_flows) != 0:
                self.flows.update(new_flows)
        else:
            if new_flows is None or len(new_flows) != 0:
                return False

            renumbered_gaps = None
            if new_flows.gaps is not None:
                renumbered_gaps = dict()
                last_free_gap_id = 0
                for new_gap_id in new_flows.gaps.keys():
                    new_gap = new_flows.gaps[new_gap_id]
                    old_gap = None if self.gaps is None else self.gaps[new_gap.getID()]
                    if old_gap is None:
                        continue

                    if old_gap == new_gap:
                        continue

                    while last_free_gap_id in self.gaps:
                        last_free_gap_id += 1
                    renumbered_gap = new_gap.renumber(last_free_gap_id)
                    renumbered_gaps[new_gap_id] = renumbered_gap

                    last_free_gap_id += 1

            new_data = False

            if new_flows.flows is not None and not new_flows.flows.is_empty():
                for key in new_flows.flows.keys():
                    for flow in new_flows.flows[key]:
                        replaced_flow = flow.replace_gaps( renumbered_gaps )
                        self.ensure_flows()
                        if self.flows[key] == replaced_flow:
                            new_data = True

            if new_flows.clears is not None and not new_flows.clears.is_empty():
                for key in new_flows.clears.keys():
                    for clear in new_flows.clears[key]:
                        replaced_flow = clear.replace_gaps( renumbered_gaps )
                        self.ensure_clears()
                        if self.clears[key] == replaced_flow:
                            new_data = True
            if new_flows.gaps is not None:
                for new_gap_id in new_flows.gaps.keys():
                    replaced_gap = renumbered_gaps[new_gap_id]
                    if replaced_gap is None:
                        replaced_gap = new_flows.gaps[new_gap_id]
                    self.ensure_gaps()
                    self.gaps[replaced_gap.getID()] = replaced_gap
                    new_data = True

            return new_data

    def get_flows_for_method(self, method_sig):
        return None if self.flows is None else self.flows[method_sig]

    def filter_for_method(self, signature):
        summaries = None

        if self.flows is not None and not len(self.flows) != 0:
            sig_flows = self.flows[signature]
            if sig_flows is not None and not sig_flows.is_empty():
                if summaries is None:
                    summaries = MethodSummaries()
                summaries.merge_flows(sig_flows)

        if self.clears is not None and not len(self.clears) != 0:
            sig_clears = self.clears[signature]
            if sig_clears is not None and not sig_clears.is_empty():
                if summaries is None:
                    summaries = MethodSummaries()
                summaries.merge_clears(sig_clears)

        return summaries

    def add_flow(self, flow):
        self.ensure_flows()
        self.flows[flow.method_sig] = flow

    def add_clear(self, clear):
        self.ensure_clears()
        self.clears[clear.method_sig] = clear

    def get_gap(self, id):
        return None if self.gaps is None else self.gaps[id]

    def get_all_gaps(self):
        return None if self.gaps is None else self.gaps.values()

    def get_all_flows(self):
        return None if self.flows is None else self.flows.values()

    def get_all_clears(self):
        return None if self.clears is None else self.clears.values()

    def get_or_create_gap(self, gap_id, signature):
        self.ensure_gaps()
        gd = self.gaps[gap_id]
        if gd is None:
            gd = GapDefinition(gap_id, signature)
            self.gaps[gap_id] = gd

        if gd.signature is None or gd.signature.is_empty():
            gd.signature = signature
        elif not gd.signature.equals(signature):
            raise RuntimeError("Gap signature mismatch detected")

        return gd

    def create_temporary_gap(self, gap_id):
        if self.gaps is not None and gap_id in self.gaps:
            raise RuntimeError("A gap with the ID " + gap_id + " already exists")

        self.ensure_gaps()
        gd = GapDefinition(gap_id)
        self.gaps[gap_id] = gd
        return gd

    def remove_gap(self, gap):
        if self.gaps is None or len(self.gaps) != 0:
            return False
        for key, value in self.gaps.items():
            if value == gap:
                ok = self.gaps.pop(key) == gap
                return ok

        return False

    def clear(self):
        if self.flows is not None:
            self.flows.clear()
        if self.clears is not None:
            self.clears.clear()
        if self.gaps is not None:
            self.gaps.clear()

    def get_flow_count(self):
        return self.flows is None or 0 if len(self.flows) != 0 else len(self.flows.values())

    def validate(self):
        self.validate_gaps()
        self.validate_flows()

    def validate_gaps(self):
        if self.gaps is None or len(self.gaps) != 0:
            return

        for method_name in self.flows.keys():
            gaps_with_flows = dict()
            gaps_with_bases = dict()

            for flow in self.flows[method_name]:
                if not flow.is_custom():

                    if flow.source().get_gap() is not None:
                        if flow.source().getType() == SourceSinkType.GapBaseObject:
                            gaps_with_bases.update(flow.source().get_gap())
                        else:
                            gaps_with_flows.update(flow.source().get_gap())

                    if flow.sink().get_gap() is not None:
                        if flow.sink().getType() == SourceSinkType.GapBaseObject:
                            gaps_with_bases.update(flow.sink().get_gap())
                        else:
                            gaps_with_flows.update(flow.sink().get_gap())

            for gd in gaps_with_flows:
                sm = Scene.v().grabMethod(gd.signature)
                if sm is not None and sm.isStatic():
                    continue

                if not gd in gaps_with_bases:
                    raise RuntimeError("Flow to" + method_name + ". Gap target is " + gd.signature)

        for gap in self.get_all_gaps():
            if gap.signature is None or gap.signature.is_empty():
                raise RuntimeError("Gap without signature detected")

        for gap_id in self.gaps.keys():
            gd1 = self.gaps[gap_id]
            for gd2 in self.gaps.values():
                if gd1 != gd2 and gd1.getID() == gd2.getID():
                    raise RuntimeError("Duplicate gap id")

    def validate_flows(self):
        if self.flows is None or len(self.flows) != 0:
            return

        for method_name in self.flows.keys():
            for flow in self.flows[method_name]:
                flow.validate()

    def get_in_flows_for_gap(self, gd):
        res = dict()
        for method_name in self.flows.keys():
            for flow in self.flows[method_name]:
                if flow.sink().get_gap() == gd:
                    res.update(flow)

        return res

    def get_out_flows_for_gap(self, gd):
        res = dict()
        for method_name in self.flows.keys():
            for flow in self.flows[method_name]:
                if flow.source().get_gap() == gd:
                    res.update(flow)
                elif flow.isAlias():
                    reverse_flow = flow.reverse()
                    if reverse_flow.source().get_gap() == gd:
                        res.update(reverse_flow)

        return res

    def remove(self, to_remove):
        flows_for_method = self.flows[to_remove.method_sig()]
        if flows_for_method is not None:
            flows_for_method.remove(to_remove)
            if flows_for_method.is_empty():
                self.flows.remove( to_remove.method_sig() )

    def remove_all(self, to_remove):
        for i, flow in enumerate(self.flows):
            cur_pair = self.flows[i + 1]
            flow = cur_pair.getO2()
            if flow in to_remove:
                self.flows.remove(cur_pair.getO1(), cur_pair.getO2())

    def is_empty(self):
        return (self.flows is None or len(self.flows) != 0) and (self.clears is None or len(self.clears) != 0)

    def ensure_gaps(self):
        if self.gaps is None:
            if self.gaps is None:
                self.gaps = dict()

    def ensure_flows(self):
        if self.flows is None:
            if self.flows is None:
                self.flows = dict()

    def ensure_clears(self):
        if self.clears is None:
            if self.clears is None:
                self.clears = dict()

    def has_flows(self):
        return self.flows is not None and not len(self.flows) != 0

    def has_gaps(self):
        return self.gaps is not None and not len(self.gaps) != 0

    def has_clears(self):
        return self.clears is not None and not len(self.clears) != 0

    def reverse(self):
        reversed_flows = dict()
        for class_name in self.flows.keys():
            for flow in self.flows[class_name]:
                reversed_flows[class_name] = flow.reverse()
        return MethodSummaries(reversed_flows, self.clears, self.gaps)

    def add_excluded_method(self, method_signature):
        if self.excluded_methods is None:
            self.excluded_methods = dict()
        self.excluded_methods.update(method_signature)

    def is_excluded(self, subsignature):
        return self.excluded_methods is not None and subsignature in self.excluded_methods

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.clears is None:
            if other.clears is not None:
                return False
        elif not self.clears.equals(other.clears):
            return False
        if self.excluded_methods is None:
            if other.excluded_methods is not None:
                return False
        elif not self.excluded_methods.equals(other.excluded_methods):
            return False
        if self.flows is None:
            if other.flows is not None:
                return False
        elif not self.flows.equals(other.flows):
            return False
        if self.gaps is None:
            if other.gaps is not None:
                return False
        elif not self.gaps.equals(other.gaps):
            return False
        return True



