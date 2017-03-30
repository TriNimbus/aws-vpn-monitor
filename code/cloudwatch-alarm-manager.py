from __future__ import print_function
import json
import ast
import os
import boto3
import logging
import datetime
from urllib2 import Request
from urllib2 import urlopen

log = logging.getLogger()
log.setLevel(logging.INFO)

log.debug('Loading function')

Statistic='Average'
Period=60
Threshold=1.5
EvaluationPeriods=2


def lambda_handler(event, context):

    if not 'alarmSNS' in os.environ.keys():
        raise ValueError("Environment variables not defined.  Need 'alarmSNS' ")

    if 'cw_namespace' in os.environ.keys():
        Namespace=os.environ['cw_namespace']
    else:
        Namespace='VPNStatus'

    if 'alarm_enabled' in os.environ.keys():
        AlarmEnabled=os.environ['alarm_enabled']
    else:
        AlarmEnabled=True

    ec2 = boto3.client('ec2')
    AWS_Regions = ec2.describe_regions()['Regions']
    for region in AWS_Regions:
        try:
            cw = boto3.client('cloudwatch', region_name=region['RegionName'])
            metrics = cw.list_metrics(Namespace=Namespace)['Metrics']

            for m in metrics:
                res = cw.describe_alarms_for_metric(
                    MetricName=m['MetricName'],
                    Namespace=m['Namespace'])
                if not res['MetricAlarms']:
                    print("Will create MetricAlarm for {}:{}".format(m['Namespace'],m['MetricName']))
                    ret=cw.put_metric_alarm(
                        AlarmName='alarm_{}'.format(m['MetricName']),
                        AlarmDescription="alert for VPN tunnels {}".format(m['MetricName']),
                        ActionsEnabled=ast.literal_eval(AlarmEnabled),
                        MetricName=m['MetricName'],
                        Namespace=m['Namespace'],
                        Statistic=Statistic,
                        Dimensions=m['Dimensions'],
                        Period=Period,
                        Threshold=Threshold,
                        EvaluationPeriods=EvaluationPeriods,
                        ComparisonOperator='LessThanOrEqualToThreshold',
                        AlarmActions= [ os.environ['alarmSNS'] ]
                        )
        except Exception as e:
            log.error("Exception: "+str(e))
            continue
