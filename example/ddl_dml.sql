CREATE SCHEMA ORG;
CREATE TABLE ORG.EMPLY
(	ACCT_NB int NOT NULL, 
	Sex char(10),
	Location varchar(30),
	Position varchar(20),
	Ranking int,
	Department varchar(30) 
);


INSERT INTO ORG.EMPLY (ACCT_NB, Sex, Location, Position, Ranking, Department)
VALUES 
('14567391','Male','Chicago','Developer','36','Technology'),
('12567392','Male','Manhattan,NY','','38','Business'),
('86567894','Female','Rockville,MD','Legal Advisor','40','Legal'),
('17567894','','Ashburn,VA','DBA','38','Technology'),
('93595894','Female','Rockville,MD','Manager','43','');

select * from org.emply;