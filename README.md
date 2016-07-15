# Check AWS CloudWatch

This repository aims to make improvements to the Nagios plugin at -->
https://exchange.nagios.org/directory/Plugins/Operating-Systems/*-Virtual-Environments/Others/Check_AWS_CloudWatch_metrics/details


#####   CHANGELIST  #####

##  1.0.1
    -   Added support for Elasticache metric (to be used with  the --elasticache-metric option)
        for instance, call it with "-f /path/to/credentials -i clusterid -a elasticache.us-west-2.amazonaws.com -E Evictions -w 10 -S Average,Minimum,Maximum"

##  1.0.0
    -   Initial fork of the Nagios AWS CloudWatch plugin (2.5.07)
