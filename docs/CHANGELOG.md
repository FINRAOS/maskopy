# CHANGELOG
***

## 2.0.0
***
* Feature: Added AWS RDS Aurora compatibility 
* Feature: Added ability to retrieve latest snapshot from provided RDS instance
* Fix: Installs requests library during runtime rather than using deprecated botocore vendor requests library 
* Misc: Separated Check Inputs from 00-AuthorizeUser to 01-CheckInputs