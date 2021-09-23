"""import RefType
import SootClass
"""

class SystemClassHandler:

    def __init__(self):
        self.excludeSystemComponents = True

    def is_class_in_system_package(self, clazz):
        if isinstance(clazz, SootClass):
            return clazz is not None and self.is_class_in_system_package(clazz.name)
        elif isinstance(clazz, str):
            return (clazz.startswith("android.") or clazz.startswith("java.") or clazz.startswith("javax.")
                    or clazz.startswith("sun.") or clazz.startswith("org.omg.")
                    or clazz.startswith("org.w3c.dom.") or clazz.startswith("com.google.")
                    or clazz.startswith("com.android.")) and self.excludeSystemComponents

        elif isinstance(clazz, RefType):
            return self.is_class_in_system_package(clazz.soot_class.name)

        return False

    def is_taint_visible(self, tainted_path, method):
        if tainted_path is None:
            return True

        if not tainted_path.isInstanceFieldRef():
            return True

        if not self.is_class_in_system_package(method.declaring_class.name):
            return True

        has_system_type = tainted_path.base_type is not None and self.is_class_in_system_package(tainted_path.base_type)
        for fld in tainted_path.fields:
            cur_field_is_system = self.is_class_in_system_package(fld.type)
            if self.is_class_in_system_package(fld.declaring_class.type):
                cur_field_is_system = True

            if cur_field_is_system:
                has_system_type = True
            else:
                if has_system_type:
                    return False

        return True

    @staticmethod
    def is_stub_implementation(body):
        stub_const = "Stub!"
        for u in body.getUnits():
            stmt = u
            if stmt.containsInvokeExpr():
                iexpr = stmt.getInvokeExpr()
                target_method = iexpr.method
                if target_method.isConstructor() \
                        and target_method.declaring_class.name == "java.lang.RuntimeException":
                    if iexpr.getArgCount() > 0 and iexpr.getArg(0) == stub_const:
                        return True

        return False