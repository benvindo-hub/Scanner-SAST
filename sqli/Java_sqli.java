String id= request.getParameter("id");
String query= "select * from users where id='"+id+"'";
stmt.executeQuery(query);
