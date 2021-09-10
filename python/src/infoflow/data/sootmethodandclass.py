class SootMethodAndClass:

    def __init__(self, method_name, class_name, return_type, parameters=None, sm=None, method_and_class=None):
        if sm is None and method_and_class is None:
            self.method_name = method_name
            self.class_name = class_name
            self.return_type = return_type

            self.parameters = list() if parameters is None else parameters
            if isinstance(parameters, str) and parameters is not "":
                params = parameters.split(",")
                for s in params:
                    self.parameters.add(s)

            self.sub_signature = None
            self.signature = None

        elif sm is None and method_and_class is not None:
            self.method_name = method_and_class.method_name
            self.class_name = method_and_class.class_name
            self.return_type = method_and_class.return_type
            self.parameters = list(method_and_class.parameters)

        else:
            self.method_name = sm.name
            self.class_name = sm.declaringClass.name
            self.return_type = str(sm.getReturnType())
            self.parameters = list()
            for p in sm.getParameterTypes():
                self.parameters.append(str(p))

    def get_sub_signature(self):
        if self.sub_signature is not None:
            return self.sub_signature

        sb = ""
        if len(self.return_type) != 0:
            sb += self.return_type
            sb += " "

        sb += self.method_name
        sb += "("

        for i in range(0, len(self.parameters)):
            if i > 0:
                sb += ","
            sb += self.parameters[i].strip()

        sb += ")"
        self.sub_signature = str(sb)

        return self.sub_signature

    def get_signature(self):
        if self.signature is not None:
            return self.signature

        sb = ""
        sb += "<"
        sb += self.class_name
        sb += ": "
        if not len(self.return_type) != 0:
            sb += self.return_type
            sb += " "

        sb += self.method_name
        sb += "("

        for i in range(0, len(self.parameters)):
            if i > 0:
                sb += ","
            sb += self.parameters[i].strip()

        sb += ")>"
        self.signature = str(sb)

        return self.signature

    def equals(self, another):
        if not isinstance(another, SootMethodAndClass):
            return False
        other_method = another

        if not self.method_name.equals(other_method.method_name):
            return False
        if not self.parameters == other_method.parameters:
            return False
        if not self.class_name.equals(other_method.class_name):
            return False
        return True
