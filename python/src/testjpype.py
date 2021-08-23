import jpype
import os.path


def TestMain():

    classpath = os.path.join(os.path.abspath('../../java'), 'bin')

    print('path:', classpath)

    jpype.startJVM(jpype.getDefaultJVMPath(), "-Djava.class.path=%s" % classpath)

    testPkg = jpype.JPackage('testjpype') # get the package

    TestJPype = testPkg.TestJPype # get the class

    jc = TestJPype() # create an instance of the class

    jc.speak("This is a test message") # try to call one of the class methods

    jc.setString("Hello, World") # set a string

    s = jc.getString() # get the string back

    print(s)

    jpype.shutdownJVM()

TestMain()