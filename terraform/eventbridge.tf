 resource "aws_cloudwatch_event_rule" "security_findings" {
    name        = "${var.project_name}-security-findings"
    description = "Capture GuardDuty and Security Hub findings"
    
    event_pattern = jsonencode({
      source = ["aws.guardduty", "aws.securityhub"]
      detail-type = ["GuardDuty Finding", "Security Hub Findings - Imported"]
    })
  }

  # Target: Point the rule to the enricher Lambda
  resource "aws_cloudwatch_event_target" "enricher" {
    rule      = aws_cloudwatch_event_rule.security_findings.name
    target_id = "EnricherLambda"
    arn       = aws_lambda_function.enricher.arn
    role_arn  = aws_iam_role.eventbridge.arn
  }

  # Permission: Allow EventBridge to invoke the Lambda
  resource "aws_lambda_permission" "allow_eventbridge" {
    statement_id  = "AllowExecutionFromEventBridge"
    action        = "lambda:InvokeFunction"
    function_name = aws_lambda_function.enricher.function_name
    principal     = "events.amazonaws.com"
    source_arn    = aws_cloudwatch_event_rule.security_findings.arn
  }