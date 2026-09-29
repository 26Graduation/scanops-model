package demo;

import javax.servlet.http.HttpServletResponse;

public class Web {
    public void render(HttpServletResponse response) throws Exception {
        response.getWriter().println("constant");
    }
}
