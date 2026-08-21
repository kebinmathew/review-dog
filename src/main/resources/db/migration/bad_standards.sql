-- Rule DB-2.2: Missing purpose comment below header
CREATE OR REPLACE PROCEDURE get_emp_details_purpose (av_emp_id IN NUMBER) IS
BEGIN
    -- Rule DB-2.3: Inline changed comment without START/END CASE block
    li_status := 'ACTIVE'; -- changed
    
    -- Rule DB-2.3: Mismatched block case
    -- START CASE FIBI-4903
    NULL;
END;
/

-- Rule DB-4.1: SQL keywords select, from in lower case
select * from employee;
/

-- Rule DB-4.2: Identifiers EMP_ID, EMP_NAME in UPPER case
SELECT EMP_ID, EMP_NAME FROM employee;
/

-- Rule DB-4.3: Inconsistent table aliases (e has alias, dept doesn't)
SELECT e.emp_id FROM polus_emp_details e, polus_dept_details;
/

-- Rule DB-4.5: Schema prefix polus_schema used
SELECT * FROM polus_schema.polus_emp_details;
/

-- Rule DB-4.6: Boolean-style function returns TRUE instead of 1
CREATE OR REPLACE FUNCTION test_func_bool RETURN NUMBER IS
BEGIN
    RETURN TRUE;
END;
/

li_flag := MOD(li_count, 2);
/

SELECT * FROM employee WHERE emp_id = 100;
/

-- Rule DB-4.9: Variable declaration not using %TYPE
DECLARE
    li_emp_id NUMBER;
BEGIN
    NULL;
END;
/

-- Rule DB-4.10: Join condition after filter condition in WHERE
SELECT * FROM polus_emp_details e, polus_dept_details d WHERE e.status = 'A' AND e.dept_id = d.dept_id;
/
