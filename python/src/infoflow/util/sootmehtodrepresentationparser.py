import re

from ..data.sootmethodandclass import SootMethodAndClass


class SootMethodRepresentationParser:

    def __init__(self):
        self.pattern_subsig_to_name = None
        self.pattern_method_sig = None

    def parse_soot_method_string(self, parse_string):
        if parse_string is None or parse_string is "":
            return None

        if not parse_string.startsWith("<") or not parse_string.endsWith(">"):
            raise ValueError("Illegal format of " + parse_string + " (should use soot method representation)")

        if self.pattern_method_sig is None:
            self.pattern_method_sig = re.compile(
                "<(?P<className>.*?): (?P<returnType>.*?) (?P<methodName>.*?)\\((?P<parameters>.*?)\\)>")

        matcher = self.pattern_method_sig.match(parse_string)
        if matcher is not None:
            class_name = matcher.group("className")
            return_type = matcher.group("returnType")
            method_name = matcher.group("methodName")
            param_list = matcher.group("parameters")
            return SootMethodAndClass(method_name, class_name, return_type, param_list)

        return None

    @staticmethod
    def parse_class_names(methods, sub_signature):
        result = dict()
        pattern = re.compile("^\\s*<(.*?):\\s*(.*?)>\\s*$")
        for parse_string in methods:
            matcher = pattern.match(parse_string)
            if matcher is not None:
                class_name = matcher.group(1)
                if sub_signature:
                    params = matcher.group(2)
                else:
                    params = parse_string

                if class_name in result:
                    result.get(class_name).append(params)
                else:
                    method_list = list()
                    method_list.append(params)
                    result[class_name] = method_list

        return result

    @staticmethod
    def parse_class_names2(methods, sub_signature):
        result = dict()
        pattern = re.compile("^\\s*<(.*?):\\s*(.*?)>\\s*$")
        for parse_string in methods:
            matcher = pattern.match(parse_string)
            if matcher is not None:
                class_name = matcher.group(1)
                if sub_signature:
                    params = matcher.group(2)
                else:
                    params = parse_string
                result[class_name] = params

        return result

    def get_method_name_from_sub_signature(self, sub_signature):
        if self.pattern_subsig_to_name is None:
            pattern = re.compile("^\\s*(.+)\\s+(.+)\\((.*?)\\)\\s*$")
            self.pattern_subsig_to_name = pattern

        matcher = self.pattern_subsig_to_name.match(sub_signature)

        if matcher is None:
            pattern = re.compile("^\\s*(.+)\\((.*?)\\)\\s*$")
            self.pattern_subsig_to_name = pattern
            return self.get_method_name_from_sub_signature(sub_signature)

        method = matcher.group(len(matcher.groups()) - 1)
        return method

    def get_parameter_types_from_sub_signature(self, sub_signature):
        if self.pattern_subsig_to_name is None:
            pattern = re.compile("^\\s*(.+)\\s+(.+)\\((.*?)\\)\\s*$")
            self.pattern_subsig_to_name = pattern

        matcher = self.pattern_subsig_to_name.match(sub_signature)
        if matcher is None:
            pattern = re.compile("^\\s*(.+)\\((.*?)\\)\\s*$")
            self.pattern_subsig_to_name = pattern
            return self.get_parameter_types_from_sub_signature(sub_signature)

        params = matcher.group(len(matcher.groups()))
        if params == "":
            return None
        else:
            return params.split("\\s*,\\s*")
