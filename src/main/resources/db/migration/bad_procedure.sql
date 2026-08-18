-- Rule DB-4: DELIMITER statement in Liquibase-formatted routine
DELIMITER $$

CREATE PROCEDURE get_proposal(IN p_id INT)
BEGIN
    SELECT PROPOSAL_ID, TITLE FROM EPS_PROPOSAL WHERE PROPOSAL_ID = p_id;
END$$

DELIMITER ;

-- Rule DB-6: Hardcoded USE dbname and credentials
USE fibi_coeus;

INSERT INTO EPS_PROPOSAL (PROPOSAL_ID, TITLE, UPDATE_USER, UPDATE_TIMESTAMP)
VALUES (2001, 'Test', 'admin', NOW());
