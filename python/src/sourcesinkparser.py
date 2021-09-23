class SourceSink:

    def __init__(self, type, class_name, method_name, ret_type, params):
        self.type = type
        self.class_name = class_name
        self.method_name = method_name
        self.ret_type = ret_type
        self.params = params

    def __str__(self):
        return "[%s] %s %s.%s%s" % (self.type.upper(), self.ret_type, self.class_name, self.method_name, self.params)

    def __repr__(self):
        return self.__str__()


class SourceSinkParser:

    signature = {'_SOURCE_': 'source',
                 '_SINK_': 'sink'
                 }

    def __init__(self, sourcesinks):
        self.sourcesinks_file = open(sourcesinks)
        self.sourcesinks = [ ]
        self.sources = [ ]
        self.sinks = [ ]
        self.parse()
        self.sourcesinks = self.sources + self.sinks

    def parse(self):
        for line in self.sourcesinks_file.readlines():
            line = line.replace('\n', '')

            if any(key in line for key in self.signature.keys()):
                define, type, permission = self.parse_line(line)
                class_name, method = self.parse_define(define)
                ret_type, method_name, params = self.parse_method(method)
                source_sink = SourceSink(type, class_name, method_name, ret_type, params)
                if source_sink.type == 'source':
                    self.sources.append(source_sink)
                elif source_sink.type == 'sink':
                    self.sinks.append(source_sink)

    def parse_line(self, line: str):
        split_str = line.split(' -> ')
        assert len(split_str) == 2, "[E] parse type error %s" % line

        define = split_str[0]
        type = self.signature[split_str[1].strip()]
        permission = ""

        if '> ' in split_str[0]:
            temp_split_str = split_str[0].split('> ')
            permission = temp_split_str[1].strip()
            define = temp_split_str[0] + '>'

        return define, type, permission

    @staticmethod
    def parse_define(define: str):
        define = define.lstrip('<')
        define = define.rstrip('>')
        split_str = [split.strip() for split in define.split(':')]
        assert len(split_str) == 2, "[E] parse define error %s" % define

        return split_str[0], split_str[1]

    @staticmethod
    def parse_method(method):
        split_str = method.split(' ', 1)
        assert len(split_str) == 2, "[E] parse method error %s" % method

        ret_type = split_str[0]

        if '(' in split_str[1]:
            split_str = split_str[1].split('(')
            method_name = split_str[0]
            assert len(split_str) == 2, "[E] parse params error %s" % split_str[1]

            params = tuple(param for param in split_str[1].replace(' ', '').rstrip(')').split(','))
        else:
            split_str = split_str[1].split(')')
            method_name = split_str[0]
            params = tuple()

        return ret_type, method_name, params


if __name__ == '__main__':
    path = "F:\\연구실\\중견\\개발\\fd\\FlowDroid\\SourcesAndSinks.txt"
    ssp = SourceSinkParser(path)
    print(ssp.sources)
    print(ssp.sinks)