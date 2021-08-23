import jpype
import os.path


class Enum:
    apk = "app-debug.apk"
    sdk = "C:\\Users\\msec\\AppData\\Local\\Android\\Sdk\\platforms"
    scheme = "SourcesAndSinks.txt"
    output = "output.xml"


def start_jvm(classpath):
    print('path:', classpath)
    jpype.startJVM(jpype.getDefaultJVMPath(), "-Djava.class.path=%s" % classpath)


def get_class(class_name, package_name=None):
    if '.' in class_name:
        _splited = class_name.split('.')
        package_name = '.'.join(_splited[:-1])
        class_name = _splited[-1]

    package_py = jpype.JPackage(package_name) # get the package
    class_py = package_py.__getattribute__(class_name) # get the class

    return class_py


def run_mainclass(instance, option):
    apk = option.apk
    sdk = option.sdk
    scheme = option.scheme
    output = option.output



    options = "-a %s -d -p %s -s %s -o %s" % (apk, sdk, scheme, output)
    instance.main(options.split(" "))    # set a string

    jpype.shutdownJVM()


if __name__ == '__main__':
    classpath = os.path.abspath('../../java/bin/soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar')
    start_jvm(classpath)
    class_py = get_class('soot.jimple.infoflow.cmd.MainClass')
    instance_py = class_py  # create an instance of the class
    run_mainclass(instance_py, Enum)
