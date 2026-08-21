-- Rule DB-2.1: Missing CREATE OR REPLACE
PROCEDURE get_emp_details (av_emp_id IN NUMBER) IS
BEGIN
  -- Rule DB-3.1: SELECT ... INTO missing exception block/handlers
  SELECT polus_emp_id
    INTO li_polus_emp_id
    FROM polus_emp_details
   WHERE polus_emp_number = av_polus_emp_number;
END;
/

-- Rule DB-4.4: Drop primary key without dropping index
ALTER TABLE polus_emp_details DROP PRIMARY KEY;
/

-- Rule DB-4.11: Duplicate/self join
SELECT e.emp_id
  FROM polus_emp_details e, polus_emp_details e2
 WHERE e.dept_id = e2.dept_id;
/

-- Rule DB-5.1: Inequality comparison <> missing IS NULL handling
SELECT person_name, job_code
  FROM employee
 WHERE job_code <> 'SE';
/

-- Rule DB-1.1: Table name is too short / ambiguous
CREATE TABLE t_emp1 (
    emp_id NUMBER,
    dept_ref NUMBER
);
/

-- Rule DB-1.2: View name is too short
CREATE OR REPLACE VIEW v1 AS SELECT * FROM t_emp1;
/

-- Rule DB-1.3: Foreign key name mismatch (dept_ref vs dept_id)
ALTER TABLE polus_emp_details ADD CONSTRAINT fk_dept FOREIGN KEY (dept_ref) REFERENCES polus_dept_details (dept_id);
/

-- Rule DB-1.4: Procedure name does not start with GET/UPDATE/upd/delete/del/insert
CREATE OR REPLACE PROCEDURE emp_details_proc (av_emp_id IN NUMBER) IS
BEGIN
    NULL;
END;
/

-- Rule DB-1.5: Function name does not start with fn_
CREATE OR REPLACE FUNCTION is_active_emp (av_emp_id IN NUMBER) RETURN BOOLEAN IS
BEGIN
    RETURN TRUE;
END;
/

-- Rule DB-1.6: Package name does not start with pkg_
CREATE OR REPLACE PACKAGE emp_utils IS
    PROCEDURE test_proc;
END emp_utils;
/

-- Rule DB-1.7: Trigger name does not start with trg_
CREATE OR REPLACE TRIGGER emp_audit_trg
BEFORE INSERT ON employee
FOR EACH ROW
BEGIN
    NULL;
END;
/

-- Rule DB-1.8: Sequence name does not start with seq_
CREATE SEQUENCE emp_id_seq;
/

-- Rule DB-1.9: Parameter name does not start with av_ or aw_
CREATE OR REPLACE PROCEDURE test_params (p_emp_id IN NUMBER) IS
    -- Rule DB-1.10: Variables missing prefixes
    emp_id NUMBER;
    emp_name VARCHAR2(100);
    bad_date DATE;
BEGIN
    NULL;
END;
/
