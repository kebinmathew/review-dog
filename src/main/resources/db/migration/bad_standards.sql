-- Rule DB-2.1: Missing CREATE OR REPLACE
PROCEDURE get_emp_details (av_emp_id IN NUMBER) IS
BEGIN
  -- Rule DB-3.1: SELECT ... INTO missing exception block/handlers
  SELECT polus_emp_id
    INTO li_polus_emp_id
    FROM polus_emp_details
   WHERE polus_emp_number = av_polus_emp_number;
END;

-- Rule DB-4.4: Drop primary key without dropping index
ALTER TABLE polus_emp_details DROP PRIMARY KEY;

-- Rule DB-4.11: Duplicate/self join
SELECT e.emp_id
  FROM polus_emp_details e, polus_emp_details e2
 WHERE e.dept_id = e2.dept_id;

-- Rule DB-5.1: Inequality comparison <> missing IS NULL handling
SELECT person_name, job_code
  FROM employee
 WHERE job_code <> 'SE';

-- Rule DB-6.3: Omitted slash "/" at the end of the script file
