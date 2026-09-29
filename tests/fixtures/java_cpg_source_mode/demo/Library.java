package demo;

public class Library {
    public Process run(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }

    private Process internal(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }
}
