import jpype
import os.path


def TestMain():

    classpath = os.path.join(os.path.abspath('../../java'), 'bin')

    print('path:', classpath)

    jpype.startJVM(jpype.getDefaultJVMPath(), "-Djava.class.path=%s" % classpath)

    package_py = jpype.JPackage('testjpype') # get the package

    class_py = package_py.TestJPype # get the class

    instance_py = class_py() # create an instance of the class

    instance_py.speak("This is a test message") # try to call one of the class methods

    instance_py.setString("Hello, World") # set a string

    s = instance_py.getString() # get the string back

    print(s)

    jpype.shutdownJVM()

TestMain()