id=request.args.get("id")
query="select * from users where id='"+id+"'" 
 cursor.execute(query)

query=f"select * from users where id='{id}'"

