-- Rule DB-2.2: Purpose comment
CREATE OR REPLACE PROCEDURE test_best_practices IS
BEGIN
    -- Rule DB-5.2: Update column not in WHERE clause
    UPDATE students SET status = 1 WHERE marks > 90;
    
    -- Rule DB-5.3: Column function in WHERE
    SELECT name FROM student WHERE to_num(status) = 1;
    
    -- Rule DB-5.4: NOT IN subquery
    SELECT name FROM employee WHERE user_name NOT IN (SELECT user_id FROM user_table);
    
    -- Rule DB-5.5: LIKE used for exact match
    SELECT name FROM employee WHERE job_code LIKE 'SE';
    
    -- Rule DB-5.6: COUNT(*) used
    SELECT COUNT(*) FROM employee;
    
    -- Rule DB-5.7: Literal comparison instead of bind/param
    SELECT ename FROM emp WHERE deptno = 20;
    
    -- Rule DB-5.8: DISTINCT with join
    SELECT DISTINCT d.deptno FROM dept d, emp e WHERE d.deptno = e.deptno;
    
    -- Rule DB-5.9: Comma join driving table order suggestion
    SELECT * FROM TAB1, TAB2;
END;
/
