#     Copyright 2016 Bridgewater Associates
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.alerters.custom_alerter
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Bridgewater OSS <opensource@bwater.com>


"""
from security_monkey import app
import boto3
from security_monkey.datastore import db, ItemRevision
import json
sns = boto3.client('sns', region_name='us-east-2')

alerter_registry = []

class AlerterType(type):
    def __init__(self, cls, name, bases, attrs):
        if getattr(cls, "report_auditor_changes", None) and getattr(cls, "report_watcher_changes", None):
            app.logger.debug("Registering alerter %s", cls.__name__)
            alerter_registry.append(cls)

def publish_to_sns(Message):
    sns.publish(
        TopicArn='arn:aws:sns:us-east-2:254099312441:security-monkey-custom-alerter-topic',
        Message=Message
    )
    return True

def report_auditor_changes(auditor):
       for item in auditor.items:

            for issue in item.confirmed_new_issues:
                # Create a text output of your auditor new issue in scope
                revisions = db.session.query(ItemRevision).filter(ItemRevision.item_id == issue.item_id).order_by(ItemRevision.date_created.desc())
                revisions_list = list(revisions.all())
                if len(revisions_list) > 1:
                    old_config = revisions_list[1].config
                else:
                    old_config = item.old_config

                if issue.justified == False and issue.fixed == False:
                    attachment = '"Confirmed New Issue":\n\n"Account": "{}"\n\n"Region": "{}"\n\n"Index": "{}"\n\n"ARN": "{}"\n\n"ItemName": "{}"\n\n"ItemActive": "{}"\n\n"ItemFoundNewIssues": "{}"\n\n"AuditIssues": "{}"\n\n"ConfirmedNewIssues": "{}"\n\n"NewConfig": "{}"\n\n"OldConfig": "{}"\n\n"ActionInstructions": "{}"\n\n"BackgroundInfo": "{}"\n\n"Fixed": "{}"\n\n"IssueID": "{}"\n\n"Issue": "{}"\n\n"ItemID": "{}"\n\n"Justification": "{}"\n\n"Justified": "{}"\n\n"JustifiedDate": "{}"\n\n"JustifiedUserID": "{}"\n\n"Notes": "{}"\n\n"Origin": "{}"\n\n"OriginSummary": "{}"\n\n"IssueScore": "{}"'.format(item.account, item.region, item.index, item.arn, item.name, item.active, item.found_new_issue, item.audit_issues, item.confirmed_new_issues, item.new_config, old_config, issue.action_instructions, issue.background_info, issue.fixed, issue.id, issue.issue, issue.item_id, issue.justification, issue.justified, issue.justified_date, issue.justified_user_id, issue.notes, issue.origin, issue.origin_summary, issue.score, issue.user)
                    attachment = "'Account': '{}','Region': '{}','Index': '{}','ARN': '{}','ItemName': '{}','ItemFoundNewIssues': '{}','NewConfig': '{}','OldConfig': '{}','ActionInstructions': '{}','BackgroundInfo': '{}','Fixed': '{}','IssueID': '{}','Issue': '{}','ItemID': '{}','Justification': '{}','Justified': '{}','JustifiedDate': '{}','JustifiedUserID': '{}','Notes': '{}','Origin': '{}','OriginSummary': '{}','IssueScore': '{}'".format(item.account, item.region, item.index, item.arn, item.name, item.found_new_issue, item.new_config, old_config, issue.action_instructions, issue.background_info, issue.fixed, issue.id, issue.issue, issue.item_id, issue.justification, issue.justified, issue.justified_date, issue.justified_user_id, issue.notes, issue.origin, issue.origin_summary, issue.score, issue.user),                    app.logger.info("Custom Alerter: {}".format(attachment))
                    Message = {
                        "Item": {
                            "Account": item.account,
                            "Region": item.region,
                            "Index": item.index,
                            "ARN": item.arn,
                            "ItemName": item.name,
                            "ItemFoundNewIssues": item.found_new_issue
                        },
                        "Issue": {
                            "ActionInstructions": issue.action_instructions,
                            "BackgroundInfo": issue.background_info,
                            "Fixed": issue.fixed,
                            "IssueID": issue.id,
                            "Issue": issue.issue,
                            "ItemID": issue.item_id,
                            "Justification": issue.justification,
                            "Justified": issue.justified,
                            "JustifiedUserID": issue.justified_user_id,
                            "Notes": issue.notes,
                            "OriginSummary": issue.origin_summary,
                            "IssueScore": issue.score
                        },
                        "NewConfig": item.new_config,
                        "OldConfig": old_config
                    }
                    attachment = json.dumps(Message)
                    publish_to_sns(attachment)
