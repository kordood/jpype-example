package testjpype;

public class TestJPype  {

    private String msg;

    public TestJPype()      {

    }

    public void speak(String msg)      {

        System.out.println(msg);

    }

    public void setString(String s)      {

        msg = s;

    }

    public String getString()      {

        return msg;

    }

}