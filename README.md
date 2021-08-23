# jpype-example
Playground of using the JPype


## testjpype_1

### java step
1. Write java source
2. Build java source to class ```javac <source_file> -d <Project_dir>/java/bin```

### python step
Require) The arch of python interpreter have to be same with the jdk. (32bit / 64bit)
1. Set classpath
2. Run JVM ```jpype.startJVM(jpype.getDefaultJVMPath(), "-Djava.class.path=%s" % classpath)```
3. Get package ```package_py = jpype.JPackage(<package_name>```
4. Get class ```class_py = package_py.<class_name>```
5. Get instance ```instance_py = class_py()```
6. Use method ```instance_py.<method_name>```
7. Shutdown JVM ```jpype.shutdownJVM()```
