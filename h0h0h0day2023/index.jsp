<%@ page import="java.sql.*" %>
<!DOCTYPE html>
<html>
<style>
form {
  width: 50px;
  padding: 10px;
}
</style>
<title>Simple database viewer</title>
<form method="POST">
  <label>Driver:</label>
  <select name=driver>
    <option value=mysql>MySQL</option>
    <option value=mariadb>MariaDB</option>
    <option value=db2>DB2</option>
    <option value=sqlserver>MSSQL</option>
    <option value=h2>H2</option>
  </select>
  <label>Host:</label>
  <input name=host />
  <label>Port:</label>
  <input name=port />
  <label>Username:</label>
  <input name=username />
  <label>Password:</label>
  <input name=password type=password />
  <label>Query:</label>
  <input name=query type=text placeholder="SELECT * FROM TABLE" />
  <input type=submit>
</form>
<%

try {
  String url = "jdbc:" + request.getParameter("driver") + "://" + request.getParameter("host") + ":" + request.getParameter("port");

  Connection con = DriverManager.getConnection(url, request.getParameter("username"), request.getParameter("password"));
  Statement stmt = con.createStatement();
  stmt.execute(request.getParameter("query"));
  ResultSet rs = stmt.getResultSet();
  ResultSetMetaData rsmd = rs.getMetaData();
  int columnCount = rsmd.getColumnCount();
  out.println("<table>");
  while (rs.next()) {
    out.println("<tr>");
    for (int i = 1; i <= columnCount; i++) {
      out.println("<td>");
      out.println(rs.getString(i));
      out.println("</td>");
    }
    out.println("</tr>");
  }
  out.println("</table>");
} catch(Exception e) {
  out.println(e.getMessage());
}

%>
</html>
