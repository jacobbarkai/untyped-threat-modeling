resource "aws_api_gateway_rest_api" "public" {
  name          = "patient-portal"
  authorization = "NONE"
  stage         = "prod"
}

resource "aws_lambda_function" "report_generator" {
  function_name = "report-generator"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_exec.arn
  vpc_config    = "none"
  trigger       = aws_api_gateway_rest_api.public.id
}

resource "aws_iam_role" "lambda_exec" {
  name   = "lambda-exec"
  policy = "AdministratorAccess"
}

resource "aws_db_instance" "records" {
  engine              = "postgres"
  publicly_accessible = false
  subnet              = "private"
  accessed_by         = aws_lambda_function.report_generator.arn
}

resource "aws_s3_bucket" "exports" {
  bucket     = "patient-exports"
  acl        = "public-read"
  versioning = false
  written_by = aws_lambda_function.report_generator.arn
}

resource "medical_device_ble_pairing" "bedside_monitor" {
  pairing_mode = "just_works"
  firmware     = "2.1.0"
  uplink       = aws_api_gateway_rest_api.public.id
}
