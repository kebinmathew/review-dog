-- Rule DB-6.5 Large data scripts kept separate
ALTER TABLE employee ADD salary NUMBER;

INSERT INTO employee (emp_id, emp_name) VALUES (1, 'User 1');
INSERT INTO employee (emp_id, emp_name) VALUES (2, 'User 2');
INSERT INTO employee (emp_id, emp_name) VALUES (3, 'User 3');
INSERT INTO employee (emp_id, emp_name) VALUES (4, 'User 4');
INSERT INTO employee (emp_id, emp_name) VALUES (5, 'User 5');
INSERT INTO employee (emp_id, emp_name) VALUES (6, 'User 6');
INSERT INTO employee (emp_id, emp_name) VALUES (7, 'User 7');
INSERT INTO employee (emp_id, emp_name) VALUES (8, 'User 8');
INSERT INTO employee (emp_id, emp_name) VALUES (9, 'User 9');
INSERT INTO employee (emp_id, emp_name) VALUES (10, 'User 10');
INSERT INTO employee (emp_id, emp_name) VALUES (11, 'User 11');
/
