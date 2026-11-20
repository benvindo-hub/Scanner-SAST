id="djfjfg"
query="select * from users where id='"+id+"'"
cursor.execute(query)

id2="dkjf"
query2=f"select * from users where id='{id2}'"
cursor.execute(query2)
 
cursor.executemany(="insert into users values ("+vals+")")

cursor.executescript("drop table "+table)

User.objects.raw("select * from users where id = "+user_id) 


User.objects.extra(where=["id = "+user_id])
