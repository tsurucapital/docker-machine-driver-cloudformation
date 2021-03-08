package main

/*
 * Main program entry-point
 * ------------------------
 */

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/drivers/plugin"
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
var DriverVersion = "0.3.0"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("%s %s\n\n", path.Base(os.Args[0]), DriverVersion)

		return
	}

	plugin.RegisterDriver(
		&Driver{
			BaseDriver: &drivers.BaseDriver{
				SSHUser: "root",
				SSHPort: 22,
			},
		},
	)
}

// ClientConfig comment
type ClientConfig struct {
	session *session.Session
	config  *aws.Config
}

// Driver comment??
type Driver struct {
	*drivers.BaseDriver
	CreateStackInput         cloudformation.CreateStackInput
	cloudformation           *cloudformation.CloudFormation
	ec2                      *ec2.EC2
	ssm                      *ssm.SSM
	region                   string
	machineNameParameterName string
	spotFleetIDOutputName    string
	cloudformationRole       *string
	cloudformationStackName  *string
	clientConfig             *ClientConfig
	instanceSSHUser          string
	sshPrivateKeyParamater   *string
	sshPublicKeyParameter    *string
	stackCreationTimeout     time.Duration
	driverDebug              bool
}

// DriverName used to self-identify. Allows for clean-ups etc.
func (driver *Driver) DriverName() string {
	return "cloudformation"
}

func (driver *Driver) getClientConfig() (*ClientConfig, error) {
	if driver.clientConfig == nil {
		sess := session.Must(session.NewSession())
		config := &aws.Config{
			Region: aws.String(driver.region),
		}

		if driver.driverDebug {
			config.WithLogLevel(aws.LogDebugWithRequestRetries)
		}

		if driver.cloudformationRole != nil {
			config.Credentials = stscreds.NewCredentials(sess, *driver.cloudformationRole)
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
	if driver.sshPrivateKeyParamater == nil {
		return fmt.Errorf("Private SSH key parameter has to be set, check --help")
	}

	if driver.sshPublicKeyParameter == nil {
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
		Name:           driver.sshPrivateKeyParamater,
		WithDecryption: &WithDecryption,
	})

	if err != nil {
		log.Errorf("Failed to read the %s parameter.", *driver.sshPrivateKeyParamater)
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
		Name:           driver.sshPublicKeyParameter,
		WithDecryption: &WithDecryption,
	})
	if err != nil {
		log.Errorf("Failed to read the %s parameter.", *driver.sshPublicKeyParameter)
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

	// Before we create stack, we have to set then name and bunch of parameters.
	driver.CreateStackInput.SetStackName(driver.MachineName)
	stackParameters := []*cloudformation.Parameter{
		{
			ParameterKey:   &driver.machineNameParameterName,
			ParameterValue: &driver.MachineName,
		},
	}
	driver.CreateStackInput.SetParameters(stackParameters)

	stack, err := cfClient.CreateStack(&driver.CreateStackInput)
	if err != nil {
		log.Errorf("Failed to create %s stack.", *driver.CreateStackInput.StackName)
		return err
	}
	log.Debugf("Created %s stack, waiting for it to come up", *driver.CreateStackInput.StackName)

	// Store the name so we can destroy it later. It's technically always
	// available but we can check if we actually provisioned it quickly via a
	// second field.
	driver.cloudformationStackName = driver.CreateStackInput.StackName

	describeStack := &cloudformation.DescribeStacksInput{
		StackName: stack.StackId,
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), driver.stackCreationTimeout)

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

	params := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(*workerInstance.InstanceId)},
	}
	log.Debugf("describing instance %s", *workerInstance.InstanceId)
	resp, err := ec2Client.DescribeInstances(params)
	if err != nil {
		log.Errorf("failed to distribe instance %s", *workerInstance.InstanceId)
		return err
	}

	var instance *ec2.Instance
	for _, res := range resp.Reservations {
		for _, i := range res.Instances {
			if i.InstanceId == workerInstance.InstanceId {
				instance = i
				break
			}
		}
	}

	if instance == nil {
		return fmt.Errorf("expected to find instance with ID %s but it was missing", *workerInstance.InstanceId)
	}

	log.Debugf("Instance was launched with IP %s", *instance.PrivateIpAddress)

	driver.IPAddress = *instance.PrivateIpAddress
	driver.SSHUser = driver.instanceSSHUser

	return nil
}

// GetCreateFlags todo
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
			Usage: "Number of seconds to wait for stack creation to complete",
			Value: 300,
		},
		mcnflag.BoolFlag{
			Name:  "cloudformation-driver-debug",
			Usage: "Whether to turn debugging output on, regardless of docker-machine --debug.",
		},
	}
}

// GetSSHHostname returns the hostname for SSH
func (driver *Driver) GetSSHHostname() (string, error) {
	// TODO: Check machine has been created.

	return driver.IPAddress, nil
}

// GetState retrieves the status of the target Docker Machine instance in CloudControl.
func (driver *Driver) GetState() (state.State, error) {
	return state.Running, nil
}

// GetURL returns docker daemon URL on the target machine
func (driver *Driver) GetURL() (string, error) {
	if driver.IPAddress == "" {
		return "", nil
	}

	url := fmt.Sprintf("tcp://%s", net.JoinHostPort(driver.IPAddress, "2376"))

	return url, nil
}

// Kill the target machine (hard shutdown).
func (driver *Driver) Kill() error {
	return errors.New("the CloudFormation driver does not support Kill")
}

// Remove deletes the target machine.
func (driver *Driver) Remove() error {
	log.Infof("Destroying resources...")
	return driver.DestroyCloudFormationStack()
}

// DestroyCloudFormationStack destroys the CF stack if it exists
func (driver *Driver) DestroyCloudFormationStack() error {
	if driver.cloudformationStackName == nil {
		log.Warnf("no CloudFormation stack found in driver state, not destroying anything")
		return nil
	}

	cfClient, err := driver.getCloudFormationClient()

	if err != nil {
		log.Errorf("Unable to get CloudFormation client, CF stack %s may be left behind.", *driver.cloudformationStackName)
		return err
	}

	_, err = cfClient.DeleteStack(&cloudformation.DeleteStackInput{
		RoleARN:   driver.cloudformationRole,
		StackName: driver.cloudformationStackName,
	})

	if err != nil {
		log.Errorf("Deleting %s stack failed, resources may have been left behind.", *driver.cloudformationStackName)
		return err
	}

	driver.cloudformationStackName = nil

	return nil
}

// Restart the target machine.
func (driver *Driver) Restart() error {
	// TODO: Check machine has been created.

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

	driver.CreateStackInput.SetTemplateURL(flags.String("cloudformation-template-url"))

	role := flags.String("cloudformation-creation-role")
	// We only set the role if it's set to some value. It's easier to work with
	// nil as bunch of places in the API expect pointers.
	if role != "" {
		driver.cloudformationRole = &role
	}

	driver.region = flags.String("cloudformation-region")

	driver.instanceSSHUser = flags.String("cloudformation-instance-ssh-user")

	driver.machineNameParameterName = flags.String("cloudformation-machine-name-parameter-name")

	driver.spotFleetIDOutputName = flags.String("cloudformation-spot-fleet-id-output-name")

	private := flags.String("cloudformation-ssh-private-key-parameter")
	if private != "" {
		driver.sshPrivateKeyParamater = &private
	}

	public := flags.String("cloudformation-ssh-public-key-parameter")
	if public != "" {
		driver.sshPublicKeyParameter = &public
	}

	timeout := time.Duration(flags.Int("cloudformation-stack-creation-timeout")) * time.Second
	if timeout <= 0 {
		return fmt.Errorf("Stack timeout duration has to be positive but got %f seconds", timeout.Seconds())
	}
	driver.stackCreationTimeout = timeout

	return nil
}

// Start the target machine.
func (driver *Driver) Start() error {
	return errors.New("the CloudFormation driver does not support Start")
}

// Stop the target machine (gracefully).
func (driver *Driver) Stop() error {
	return errors.New("the CloudFormation driver does not support Stop")
}
