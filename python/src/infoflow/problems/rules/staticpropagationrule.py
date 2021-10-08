from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...infoflowconfiguration import StaticFieldTrackingMode


class StaticPropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        static_field_mode = self.manager.config.getStaticFieldTrackingMode()

        if static_field_mode == StaticFieldTrackingMode._None:
            if dest.isStaticInitializer() or source.getAccessPath().isStaticFieldRef():
                kill_all.value = True
                return None

        ap = source.getAccessPath()

        if ap.isStaticFieldRef():
            is_lazy_analysis = False
            aliasing = self.manager.aliasing
            if aliasing is not None:
                strategy = aliasing.getAliasingStrategy()
                is_lazy_analysis = strategy is not None and strategy.isLazyAnalysis()

            if is_lazy_analysis or self.manager.icfg.isStaticFieldRead(dest, ap.getFirstField()):
                new_abs = source.deriveNewAbstraction(ap, stmt)
                if new_abs is not None:
                    return [new_abs]

        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        if self.manager.config.getStaticFieldTrackingMode() == StaticFieldTrackingMode._None \
                and source.getAccessPath().isStaticFieldRef():
            kill_all.value = True
            return None

        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        if not source.getAccessPath().isStaticFieldRef():
            return None

        if self.manager.config.getStaticFieldTrackingMode() == StaticFieldTrackingMode._None \
                and source.getAccessPath().isStaticFieldRef():
            kill_all.value = True
            return None

        return [source.deriveNewAbstraction(source.getAccessPath(), stmt)]
