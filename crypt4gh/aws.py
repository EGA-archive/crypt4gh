
import boto3
import logging
import sys

"""
Handy dandy utilities for dealing with AWS resources
"""

LOG = logging.getLogger(__name__)

def get_parameter(param_name):
    """
    This function reads a secure parameter from AWS' SSM service.
    The request must be passed a valid parameter name, as well as 
    temporary credentials which can be used to access the parameter.
    The parameter's value is returned.
    """

    # Create the SSM Client
    ssm = boto3.client('ssm')

    # Get the requested parameter
    response = ssm.get_parameters(
        Names=[
            param_name,
        ],
        WithDecryption=True
    )
    
    if len(response['Parameters']) == 0:
        LOG.critical("AWS SSM parameter %s not found." % param_name)
        LOG.critical("Please check the name of the key is correct and the credentials in your environment have appropriate authorisation.")
        sys.exit(1)

    credentials = response['Parameters'][0]['Value']

    return credentials