id=request.args.get("id")
query="select * from users where id='"+id+"'"
cursor.execute(query)

query2=f"select * from users where id='{id}'"
cursor.execute(query2)
