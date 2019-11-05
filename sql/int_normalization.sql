
INSERT INTO NORMALIZATION ( original_name, key ) 	
SELECT
	L.name,
	L.key
FROM
	normalization N 
right join
(select name,key from hostsoftwares group by  name, key order by name) L ON N.key = L.key AND N.original_name = L.name
WHERE
 N.original_name is NULL AND
 N.key is NULL


