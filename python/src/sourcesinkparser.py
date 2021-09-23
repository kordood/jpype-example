test_str = [
    "<com.novell.ldap.rfc2251.RfcFilter: void addSubstring(int,byte[])> -> _SINK_",
    "<org.xmldb.api.base.XMLDBException: void printStackTrace(java.io.PrintWriter)> -> _SINK_",
    "<org.springframework.security.config.http.FormLoginBeanDefinitionParser: java.lang.String getLoginPage)> -> _SOURCE_",


]


class SourceSinkParser:

    signature = {'source': "_SOURCE_",
                 'sink': "_SINK_"
                 }

    def __init__(self, sourcesinks):
        self.sourcesinks_file = open(sourcesinks)
        self.sourcesinks = self.sourcesinks_file.readlines()
        self.sources = [ ]
        self.sinks = [ ]
        self.parse()
