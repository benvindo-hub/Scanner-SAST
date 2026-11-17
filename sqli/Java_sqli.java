String id= request.getParameter("id");
String query= "select * from users where id='"+id+"'";
stmt.executeQuery(query);
stmt.execute("SELECT * FROM users WHERE id = "+userId)
stmt.executeUpdate("DELETE FROM users WHERE id = "+userId)
