package main

/*
 * Main program entry-point
 * ------------------------
 */

import (
	"context"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
)

// DriverVersion of this driver
var DriverVersion = "0.8.0"

// ClientConfig comment
type ClientConfig struct {
	session *session.Session
	config  *aws.Config
}

// Driver comment??
type Driver struct {
	*drivers.BaseDriver
	cloudformation           *cloudformation.CloudFormation
	ec2                      *ec2.EC2
	ssm                      *ssm.SSM
	MachineNameParameterName string
	spotFleetIDOutputName    string
	clientConfig             *ClientConfig
	InstanceSSHUser          string
	SSHPrivateKeyParameter   *string
	SSHPublicKeyParameter    *string
	StackCreationTimeout     time.Duration
	driverDebug              bool
	InstanceStartTimeout     time.Duration
	InstanceStopTimeout      time.Duration

	StackName          *string
	StackTemplateURL   string
	InstanceID         *string
	Region             *string
	CloudFormationRole *string

	StackTags []*cloudformation.Tag
}

// StateFile ensures that directory for a state file exists and returns the path
// to the file we should write/read to. Does not do anything with the file.
func (driver *Driver) StateFile() (*string, error) {
	stateFile := driver.ResolveStorePath(fmt.Sprintf("%s-driver-state.json", driver.GetMachineName()))
	stateFileDir := filepath.Dir(stateFile)
	if _, err := os.Stat(stateFileDir); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(stateFileDir), 0744)
		if err != nil {
			return nil, err
		}
	}
	return &stateFile, nil
}

// DriverName used to self-identify. Allows for clean-ups etc.
func (driver *Driver) DriverName() string {
	return "cloudformation"
}

func (driver *Driver) getClientConfig() (*ClientConfig, error) {
	if driver.clientConfig == nil {
		sess := session.Must(session.NewSession())
		if driver.Region == nil {
			return nil, fmt.Errorf("region not set in driver state")
		}

		config := &aws.Config{
			Region: aws.String(*driver.Region),
		}

		if driver.driverDebug {
			config.WithLogLevel(aws.LogDebug)
		}

		if driver.CloudFormationRole != nil {
			config.Credentials = stscreds.NewCredentials(sess, *driver.CloudFormationRole)
		}

		driver.clientConfig = &ClientConfig{
			session: sess,
			config:  config,
		}
	}
	return driver.clientConfig, nil
}

func (driver *Driver) getCloudFormationClient() (*cloudformation.CloudFormation, error) {

	if driver.cloudformation == nil {
		config, err := driver.getClientConfig()
		if err != nil {
			return nil, err
		}

		driver.cloudformation = cloudformation.New(config.session, config.config)
	}

	return driver.cloudformation, nil
}

func (driver *Driver) getEc2Client() (*ec2.EC2, error) {
	if driver.ec2 == nil {
		config, err := driver.getClientConfig()
		if err != nil {
			return nil, err
		}

		driver.ec2 = ec2.New(config.session, config.config)
	}
	return driver.ec2, nil
}

func (driver *Driver) getSsmClient() (*ssm.SSM, error) {
	if driver.ssm == nil {
		config, err := driver.getClientConfig()
		if err != nil {
			return nil, err
		}

		driver.ssm = ssm.New(config.session, config.config)
	}
	return driver.ssm, nil
}

// PreCreateCheck verifies some flag values.
func (driver *Driver) PreCreateCheck() error {
	if driver.SSHPrivateKeyParameter == nil {
		return fmt.Errorf("Private SSH key parameter has to be set, check --help")
	}

	if driver.SSHPublicKeyParameter == nil {
		return fmt.Errorf("Public SSH key parameter has to be set, check --help")
	}

	return nil
}

// Create register a SSH key pair, applies CloudFormation stack and waits until
// an instance is ready.
func (driver *Driver) Create() error {
	log.Infof("Creating resources...")

	// We start by importing private and public keys into the docker machine
	// directory.
	ssmClient, err := driver.getSsmClient()
	if err != nil {
		return err
	}

	WithDecryption := true
	private, err := ssmClient.GetParameter(&ssm.GetParameterInput{
		Name:           driver.SSHPrivateKeyParameter,
		WithDecryption: &WithDecryption,
	})

	if err != nil {
		log.Errorf("Failed to read the %s parameter.", *driver.SSHPrivateKeyParameter)
		return err
	}

	dest := driver.GetSSHKeyPath()
	destDir := filepath.Dir(dest)
	// Usually the directory doesn't exist at this point so we have to make it.
	if _, err = os.Stat(destDir); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(destDir), 0744)
		if err != nil {
			log.Errorf("Failed to make directory for SSH keys at %s", destDir)
			return err
		}
		log.Debugf("Created %s for SSH keys", destDir)
	}

	// We should have the directory now, write the private part of the SSH key.
	err = ioutil.WriteFile(dest, []byte(*private.Parameter.Value), 0400)
	if err != nil {
		log.Errorf("Failed to write private part of ssh key to %s", dest)
		return err
	}
	log.Debugf("Wrote private part of SSH key to %s", dest)
	// Set the path for good measure though I think it doesn't make a difference?
	driver.SSHKeyPath = dest

	public, err := ssmClient.GetParameter(&ssm.GetParameterInput{
		Name:           driver.SSHPublicKeyParameter,
		WithDecryption: &WithDecryption,
	})
	if err != nil {
		log.Errorf("Failed to read the %s parameter.", *driver.SSHPublicKeyParameter)
		return err
	}

	publicDest := dest + ".pub"
	err = ioutil.WriteFile(publicDest, []byte(*public.Parameter.Value), 0400)
	if err != nil {
		log.Errorf("Failed to write public part of ssh key to %s", publicDest)
		return err
	}
	log.Debugf("Wrote public part of SSH key to %s", publicDest)

	ec2Client, err := driver.getEc2Client()
	if err != nil {
		log.Errorf("Failed to get EC2 client.")
		return err
	}

	cfClient, err := driver.getCloudFormationClient()
	if err != nil {
		log.Errorf("Failed to get CloudFormation client.")
		return err
	}

	CreateStackInput := cloudformation.CreateStackInput{}
	// Before we create stack, we have to set then name and bunch of parameters.
	CreateStackInput.SetStackName(driver.MachineName)
	stackParameters := []*cloudformation.Parameter{
		{
			ParameterKey:   &driver.MachineNameParameterName,
			ParameterValue: &driver.MachineName,
		},
	}
	CreateStackInput.SetParameters(stackParameters)
	CreateStackInput.SetTags(driver.StackTags)

	stack, err := cfClient.CreateStack(&CreateStackInput)
	if err != nil {
		log.Errorf("Failed to create %s stack.", *CreateStackInput.StackName)
		return err
	}
	log.Debugf("Created %s stack, waiting for it to come up", *CreateStackInput.StackName)

	// Store the name so we can destroy it later.
	driver.StackName = CreateStackInput.StackName
	if err != nil {
		return err
	}

	describeStack := &cloudformation.DescribeStacksInput{
		StackName: stack.StackId,
	}

	if driver.StackCreationTimeout.Seconds() <= 0 {
		return fmt.Errorf("Stack timeout duration has to be positive but got %f seconds", driver.StackCreationTimeout.Seconds())
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), driver.StackCreationTimeout)

	defer cancelFn()

	err = cfClient.WaitUntilStackCreateCompleteWithContext(ctx, describeStack)
	if err != nil {
		log.Errorf("Failed to wait for %s stack.", *describeStack.StackName)
		return err
	}
	log.Debugf("Done waiting for %s stack.", *describeStack.StackName)

	// We have to wait for the stack to be ready, get IP address of the machine
	// and the SSH user.
	stacksOutput, err := cfClient.DescribeStacks(describeStack)
	if err != nil {
		log.Errorf("Failed to describe %s stack.", *describeStack.StackName)
		return err
	}
	log.Debugf("Described %s stack.", *describeStack.StackName)

	// var createdStack cloudformation.Stack
	// var stack cloudformation.Stack
	var outputs []*cloudformation.Output
	if len(stacksOutput.Stacks) > 0 {
		outputs = stacksOutput.Stacks[0].Outputs
		log.Debugf("Stack outputs: %+v", outputs)
	} else {
		return fmt.Errorf("no stacks returned with id %s", *stack.StackId)
	}

	var spotFleetID *cloudformation.Output
	for _, output := range outputs {
		if *output.OutputKey == driver.spotFleetIDOutputName {
			spotFleetID = output
		}
	}

	if spotFleetID == nil {
		return fmt.Errorf("stack output didn't contain %s output", driver.spotFleetIDOutputName)
	}
	log.Debugf("Spot fleet output determined to be %s", *spotFleetID.OutputValue)

	// We finally have outputs of the stack but the instance may still not be
	// created of course. So now we query the spot fleet instances until we get
	// something.
	maxInstances := int64(1)
	describeInstances := &ec2.DescribeSpotFleetInstancesInput{
		MaxResults:         &maxInstances,
		SpotFleetRequestId: spotFleetID.OutputValue,
	}

	var workerInstance *ec2.ActiveInstance

	sleepTime := time.Second * 5
	// Gives roughly 10 minutes of tries for instance to get allocated. Maybe we
	// want to make this configurable. I couldn't find anything about
	// docker-machine imposing some kind of time-out...
	attemptsLeft := 12 * 10

	for true {
		log.Debugf("Describing spot fleet instances for %s", *spotFleetID.OutputValue)
		description, err := ec2Client.DescribeSpotFleetInstances(describeInstances)
		if err != nil {
			log.Errorf("Failed to describe spot fleet instances for %s", *spotFleetID.OutputValue)
			return err
		}

		if len(description.ActiveInstances) > 0 {
			workerInstance = description.ActiveInstances[0]
			log.Debugf("Got an instance in the spot fleet: %+v", workerInstance)
			break
		}

		if attemptsLeft > 0 {
			log.Debugf("Spot fleet instance still not available, re-trying after %f seconds, %d retries left.", sleepTime.Seconds(), attemptsLeft)
			attemptsLeft = attemptsLeft - 1
			time.Sleep(sleepTime)
		} else {
			return fmt.Errorf("instance wasn't created within expected time, giving up")
		}
	}

	// If we got this far, we should finally have workerInstance available.
	if workerInstance == nil {
		return fmt.Errorf("internal error, expected worker instance to be available at this point")
	}

	driver.InstanceID = workerInstance.InstanceId

	params := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(*workerInstance.InstanceId)},
	}
	log.Debugf("describing instance %s", *workerInstance.InstanceId)
	resp, err := ec2Client.DescribeInstances(params)
	if err != nil {
		log.Errorf("failed to describe instance %s", *workerInstance.InstanceId)
		return err
	}

	var instance *ec2.Instance
	for _, res := range resp.Reservations {
		for _, i := range res.Instances {
			if *i.InstanceId == *workerInstance.InstanceId {
				instance = i
				break
			}
		}
	}

	if instance == nil {
		return fmt.Errorf("expected to find instance with ID %s but it was missing from %+v", *workerInstance.InstanceId, resp.Reservations)
	}

	log.Debugf("Instance was launched with IP %s", *instance.PrivateIpAddress)

	driver.IPAddress = *instance.PrivateIpAddress
	driver.SSHUser = driver.InstanceSSHUser

	return nil
}

// GetCreateFlags encodes all the options to the driver
func (driver *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:  "cloudformation-template-url",
			Usage: "https://docs.aws.amazon.com/sdk-for-go/api/service/cloudformation/#CreateStackInput TemplateURL",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-creation-role",
			Usage: "Role to use for the CloudFormation session.",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-region",
			Usage: "Region to use for the CloudFormation session.",
			Value: "ap-northeast-1",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-instance-ssh-user",
			Usage: "User name to SSH as into the created instance",
			Value: "ubuntu",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-machine-name-parameter-name",
			Usage: "Parameter name in CF stack of the machine name.",
			Value: "MachineName",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-spot-fleet-id-output-name",
			Usage: "Output name in CF stack of the created spot fleet ID.",
			Value: "SpotFleetId",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-ssh-private-key-parameter",
			Usage: "SSM parameter name containing private part of SSH key pair.",
		},
		mcnflag.StringFlag{
			Name:  "cloudformation-ssh-public-key-parameter",
			Usage: "SSM parameter name containing public part of SSH key pair.",
		},
		mcnflag.IntFlag{
			Name:  "cloudformation-stack-creation-timeout",
			Usage: "Number of seconds to wait for stack creation to complete.",
			Value: 300,
		},
		mcnflag.BoolFlag{
			Name:  "cloudformation-driver-debug",
			Usage: "Whether to turn debugging output on, regardless of docker-machine --debug.",
		},
		mcnflag.IntFlag{
			Name:  "cloudformation-instance-stop-timeout",
			Usage: "Number of seconds to wait for instance to stop if requested.",
			Value: 300,
		},
		mcnflag.IntFlag{
			Name:  "cloudformation-instance-start-timeout",
			Usage: "Number of seconds to wait for instance to start if requested.",
			Value: 300,
		},
		mcnflag.StringSliceFlag{
			Name:  "cloudformation-stack-tag",
			Usage: "Key=<name>,Value=<val>",
			Value: []string{},
		},
	}
}

// GetSSHHostname returns the hostname for SSH
func (driver *Driver) GetSSHHostname() (string, error) {
	if driver.IPAddress == "" {
		return "", fmt.Errorf("we don't know the instance IP")
	}

	return driver.IPAddress, nil
}

// GetState retrieves the status of the target Docker Machine instance in CloudControl.
func (driver *Driver) GetState() (state.State, error) {
	if driver.InstanceID == nil {
		return state.None, fmt.Errorf("we don't know the instance ID so can't get the status")
	}

	ec2Client, err := driver.getEc2Client()
	if err != nil {
		return state.None, err
	}

	resp, err := ec2Client.DescribeInstanceStatus(&ec2.DescribeInstanceStatusInput{
		InstanceIds: []*string{driver.InstanceID},
	})
	if err != nil {
		return state.None, err
	}
	if len(resp.InstanceStatuses) != 1 {
		return state.None, fmt.Errorf("Expected exactly one instance status for %s but got %+v", *driver.InstanceID, resp.InstanceStatuses)
	}
	log.Debugf("Got instance statuses %+v", resp.InstanceStatuses)
	code := *resp.InstanceStatuses[0].InstanceState.Code

	// From AWS docs, 0 = pending, 16 = running, 32 = shutting-down, 48 =
	// terminated, 64 = stopping and 80 = stopped
	if code == 0 {
		return state.Starting, nil
	} else if code == 16 {
		return state.Running, nil
	} else if code == 32 {
		return state.Stopping, nil
	} else if code == 48 {
		return state.Stopped, nil
	} else if code == 64 {
		return state.Stopping, nil
	} else if code == 80 {
		return state.Stopped, nil
	}

	return state.None, fmt.Errorf("Unknown instance status code from AWS: %+v", resp.InstanceStatuses)
}

// GetURL returns docker daemon URL on the target machine
func (driver *Driver) GetURL() (string, error) {

	hostname, err := driver.GetSSHHostname()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("tcp://%s", net.JoinHostPort(hostname, "2376"))

	return url, nil
}

// Kill the target machine (hard shutdown).
func (driver *Driver) Kill() error {
	return driver.StopInstance(true)
}

// Remove deletes the target machine.
func (driver *Driver) Remove() error {
	log.Infof("Destroying resources...")

	if driver.StackName == nil {
		log.Warnf("no CloudFormation stack found in driver state, not destroying anything")
		return nil
	}

	cfClient, err := driver.getCloudFormationClient()

	if err != nil {
		log.Errorf("Unable to get CloudFormation client, CF stack %s may be left behind.", *driver.StackName)
		return err
	}

	_, err = cfClient.DeleteStack(&cloudformation.DeleteStackInput{
		RoleARN:   driver.CloudFormationRole,
		StackName: driver.StackName,
	})

	if err != nil {
		log.Errorf("Deleting %s stack failed, resources may have been left behind.", *driver.StackName)
		return err
	}

	driver.IPAddress = ""
	driver.StackName = nil
	driver.InstanceID = nil

	return nil
}

// Restart the target machine.
func (driver *Driver) Restart() error {
	// We can check if machine is running but not bothering right now... We'll
	// just check if we know of one at least.
	if driver.IPAddress == "" {
		return fmt.Errorf("we don't know the instance IP so we can't reboot")
	}

	_, err := drivers.RunSSHCommandFromDriver(driver, "sudo shutdown -r now")

	return err
}

// SetConfigFromFlags assigns and verifies the command-line arguments presented to the driver.
func (driver *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	driver.driverDebug = flags.Bool("cloudformation-driver-debug")

	// Enable ALL logging if MACHINE_DEBUG is set
	if os.Getenv("MACHINE_DEBUG") != "" || driver.driverDebug {
		stdlog.SetOutput(os.Stderr)
	}

	log.Debugf("docker-machine-driver-cloudformation %s", DriverVersion)

	driver.StackTemplateURL = flags.String("cloudformation-template-url")

	role := flags.String("cloudformation-creation-role")
	// We only set the role if it's set to some value. It's easier to work with
	// nil as bunch of places in the API expect pointers.
	if role != "" {
		driver.CloudFormationRole = &role
	}

	region := flags.String("cloudformation-region")
	driver.Region = &region

	driver.InstanceSSHUser = flags.String("cloudformation-instance-ssh-user")

	driver.MachineNameParameterName = flags.String("cloudformation-machine-name-parameter-name")

	driver.spotFleetIDOutputName = flags.String("cloudformation-spot-fleet-id-output-name")

	private := flags.String("cloudformation-ssh-private-key-parameter")
	if private != "" {
		driver.SSHPrivateKeyParameter = &private
	}

	public := flags.String("cloudformation-ssh-public-key-parameter")
	if public != "" {
		driver.SSHPublicKeyParameter = &public
	}

	driver.StackCreationTimeout = time.Duration(flags.Int("cloudformation-stack-creation-timeout")) * time.Second

	driver.InstanceStopTimeout = time.Duration(flags.Int("cloudformation-instance-stop-timeout")) * time.Second
	driver.InstanceStartTimeout = time.Duration(flags.Int("cloudformation-instance-start-timeout")) * time.Second

	tags := flags.StringSlice("cloudformation-stack-tag")
	for _, tagStr := range tags {
		tag, err := ParseTag(tagStr)
		if err != nil {
			return err
		}
		driver.StackTags = append(driver.StackTags, tag)
	}

	return nil
}

// ParseTag parses some AWS-style tags but only one at a time.
func ParseTag(input string) (*cloudformation.Tag, error) {
	r := regexp.MustCompile(`Key=(.+),Value=(.+)`)
	match := r.FindStringSubmatch(input)
	if match == nil {
		return nil, fmt.Errorf("Could not parse %s as a tag, no match., %v", input, match)
	}
	// [0] seems to have the original string..?
	if len(match) != 3 {
		return nil, fmt.Errorf("Could not parse %s as a tag, got %d matches., %v", input, len(match), match)
	}
	tag := &cloudformation.Tag{
		Key:   &match[1],
		Value: &match[2],
	}
	return tag, nil
}

// Start the target machine.
func (driver *Driver) Start() error {
	if driver.InstanceID == nil {
		return fmt.Errorf("no instance ID found in the state")
	}

	ec2Client, err := driver.getEc2Client()
	if err != nil {
		return err
	}

	_, err = ec2Client.StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{driver.InstanceID},
	})
	if err != nil {
		return err
	}

	if driver.InstanceStartTimeout.Seconds() <= 0 {
		return fmt.Errorf("Instance stop timeout duration has to be positive but got %f seconds", driver.InstanceStartTimeout.Seconds())
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), driver.InstanceStartTimeout)
	defer cancelFn()

	return ec2Client.WaitUntilInstanceRunningWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{driver.InstanceID},
	})
}

// Stop the target machine (gracefully).
func (driver *Driver) Stop() error {
	return driver.StopInstance(false)
}

// StopInstance stops underlying EC2 instance, forcefully or not depending on
// what the user wanted.
func (driver *Driver) StopInstance(force bool) error {
	if driver.InstanceID == nil {
		return fmt.Errorf("no instance ID found in the state")
	}

	ec2Client, err := driver.getEc2Client()
	if err != nil {
		return err
	}

	_, err = ec2Client.StopInstances(&ec2.StopInstancesInput{
		Force:       &force,
		InstanceIds: []*string{driver.InstanceID},
	})
	if err != nil {
		return err
	}

	if driver.InstanceStopTimeout.Seconds() <= 0 {
		return fmt.Errorf("Instance stop timeout duration has to be positive but got %f seconds", driver.InstanceStopTimeout.Seconds())
	}
	ctx, cancelFn := context.WithTimeout(context.Background(), driver.InstanceStopTimeout)
	defer cancelFn()

	// Might want a timeout flag here.
	return ec2Client.WaitUntilInstanceStoppedWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{driver.InstanceID},
	})
}
