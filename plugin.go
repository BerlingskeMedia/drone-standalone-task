package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
)

// LogTime simply logs current time in standardized format, without adding newline break on the end
func LogTime() {
	fmt.Print("[" + time.Now().Format("2006-01-02 15:04:05") + "] ")
}

// Plugin struct contains all input parameters for this plugin
type Plugin struct {
	Key                       string
	Secret                    string
	UserRoleArn               string
	Region                    string
	Family                    string
	TaskRoleArn               string
	ContainerName             string
	DockerImage               string
	Tag                       string
	Cluster                   string
	LogDriver                 string
	LogOptions                []string
	PortMappings              []string
	Environment               []string
	SecretEnvironment         []string
	SecretsManagerEnvironment []string
	Labels                    []string
	EntryPoint                []string
	DesiredCount              int64
	CPU                       int64
	Memory                    int64
	MemoryReservation         int64
	NetworkMode               string
	YamlVerified              bool
	TaskCPU                   string
	TaskMemory                string
	TaskExecutionRoleArn      string
	Compatibilities           string
	HealthCheckCommand        []string
	HealthCheckInterval       int64
	HealthCheckRetries        int64
	HealthCheckStartPeriod    int64
	HealthCheckTimeout        int64
	Ulimits                   []string
	MountPoints               []string
	Volumes                   []string
	EfsVolumes                []string
	PlacementConstraints      string

	// ServiceNetworkAssignPublicIP - Whether the task's elastic network interface receives a public IP address. The default value is DISABLED.
	ServiceNetworkAssignPublicIP string

	// ServiceNetworkSecurityGroups represents the VPC security groups to use
	// when running awsvpc network mode.
	ServiceNetworkSecurityGroups []string

	// ServiceNetworkSubnets represents the VPC security groups to use when
	// running awsvpc network mode.
	ServiceNetworkSubnets []string

	// NEW scheduled tasks parameters
	CapacityProviders    []string // [base] [weight] [name]
	EnableExecuteCommand bool
	PlatformVersion      string
	PropagateTags        bool
	DontWait             bool
	IgnoreExecutionFail  bool
	TaskTimeout          int64
	TaskKillOnTimeout    bool
	Command              []string
	Privileged           bool
}

// Struct for placement constraints.
type placementConstraintsTemplate struct {
	Type       string `json:"type"`
	Expression string `json:"expression"`
}

const (
	softLimitBaseParseErr             = "error parsing ulimits softLimit: "
	hardLimitBaseParseErr             = "error parsing ulimits hardLimit: "
	hostPortBaseParseErr              = "error parsing port_mappings hostPort: "
	containerBaseParseErr             = "error parsing port_mappings containerPort: "
	minimumHealthyPercentBaseParseErr = "error parsing deployment_configuration minimumHealthyPercent: "
	maximumPercentBaseParseErr        = "error parsing deployment_configuration maximumPercent: "
	readOnlyBoolBaseParseErr          = "error parsing mount_points readOnly: "
	placementConstraintsBaseParseErr  = "error parsing placement_constraints json: "
	capProviderBaseParseErr           = "error parsing capacity_provider Base integer: "
	weightParseErr                    = "error parsing capacity_provider Weight integer: "
	timeoutErr                        = "error - task exceeded timeout after: "
	taskFailedErr                     = "Task failed: "
)

// Exec is main body of this plugin
func (p *Plugin) Exec() error {
	fmt.Println("Drone AWS ECS Plugin built")
	awsConfig := aws.Config{}

	if len(p.Key) != 0 && len(p.Secret) != 0 {
		awsConfig.Credentials = credentials.NewStaticCredentials(p.Key, p.Secret, "")
	}
	awsConfig.Region = aws.String(p.Region)

	var svc *ecs.ECS
	sess := session.Must(session.NewSession(&awsConfig))

	// If user role ARN is set then assume role here
	if len(p.UserRoleArn) > 0 {
		awsConfigArn := aws.Config{Region: aws.String(p.Region)}
		arnCredentials := stscreds.NewCredentials(sess, p.UserRoleArn)
		awsConfigArn.Credentials = arnCredentials
		svc = ecs.New(sess, &awsConfigArn)
	} else {
		svc = ecs.New(sess)
	}

	Image := p.DockerImage + ":" + p.Tag
	if len(p.ContainerName) == 0 {
		p.ContainerName = p.Family + "-container"
	}
	// Fargate doesn't support privileged mode
	if (p.Compatibilities == "FARGATE") {
		p.Privileged = false
	}

	definition := ecs.ContainerDefinition{
		Command: []*string{},

		DnsSearchDomains:      []*string{},
		DnsServers:            []*string{},
		DockerLabels:          map[string]*string{},
		DockerSecurityOptions: []*string{},
		EntryPoint:            []*string{},
		Environment:           []*ecs.KeyValuePair{},
		Secrets:               []*ecs.Secret{},
		Essential:             aws.Bool(true),
		ExtraHosts:            []*ecs.HostEntry{},

		Image:        aws.String(Image),
		Links:        []*string{},
		MountPoints:  []*ecs.MountPoint{},
		Name:         aws.String(p.ContainerName),
		PortMappings: []*ecs.PortMapping{},

		Ulimits: []*ecs.Ulimit{},
		//User: aws.String("String"),
		VolumesFrom: []*ecs.VolumeFrom{},
		//WorkingDirectory: aws.String("String"),
		Privileged: aws.Bool(p.Privileged),
	}
	volumes := []*ecs.Volume{}

	if p.CPU != 0 {
		definition.Cpu = aws.Int64(p.CPU)
	}

	if p.Memory == 0 && p.MemoryReservation == 0 {
		definition.MemoryReservation = aws.Int64(128)
	} else {
		if p.Memory != 0 {
			definition.Memory = aws.Int64(p.Memory)
		}
		if p.MemoryReservation != 0 {
			definition.MemoryReservation = aws.Int64(p.MemoryReservation)
		}
	}

	// Volumes
	for _, volume := range p.Volumes {
		cleanedVolume := strings.Trim(volume, " ")
		parts := strings.SplitN(cleanedVolume, " ", 2)
		vol := ecs.Volume{
			Name: aws.String(parts[0]),
		}
		if len(parts) == 2 {
			vol.Host = &ecs.HostVolumeProperties{
				SourcePath: aws.String(parts[1]),
			}
		}

		volumes = append(volumes, &vol)
	}

	// EFS Volumes
	for _, efsElem := range p.EfsVolumes {
		cleanedEfs := strings.Trim(efsElem, " ")
		parts := strings.SplitN(cleanedEfs, " ", 3)
		vol := ecs.Volume{
			Name: aws.String(parts[0]),
		}
		vol.EfsVolumeConfiguration = &ecs.EFSVolumeConfiguration{
			FileSystemId:  aws.String(parts[1]),
			RootDirectory: aws.String(parts[2]),
		}

		volumes = append(volumes, &vol)
	}

	// Mount Points
	for _, mountPoint := range p.MountPoints {
		cleanedMountPoint := strings.Trim(mountPoint, " ")
		parts := strings.SplitN(cleanedMountPoint, " ", 3)

		ro, readOnlyBoolParseErr := strconv.ParseBool(parts[2])
		if readOnlyBoolParseErr != nil {
			readOnlyBoolWrappedErr := errors.New(readOnlyBoolBaseParseErr + readOnlyBoolParseErr.Error())
			fmt.Println(readOnlyBoolWrappedErr.Error())
			return readOnlyBoolWrappedErr
		}

		mpoint := ecs.MountPoint{
			SourceVolume:  aws.String(parts[0]),
			ContainerPath: aws.String(parts[1]),
			ReadOnly:      aws.Bool(ro),
		}
		definition.MountPoints = append(definition.MountPoints, &mpoint)
	}

	// Port mappings
	for _, portMapping := range p.PortMappings {
		cleanedPortMapping := strings.Trim(portMapping, " ")
		parts := strings.SplitN(cleanedPortMapping, " ", 2)
		hostPort, hostPortErr := strconv.ParseInt(parts[0], 10, 64)
		if hostPortErr != nil {
			hostPortWrappedErr := errors.New(hostPortBaseParseErr + hostPortErr.Error())
			fmt.Println(hostPortWrappedErr.Error())
			return hostPortWrappedErr
		}
		containerPort, containerPortErr := strconv.ParseInt(parts[1], 10, 64)
		if containerPortErr != nil {
			containerPortWrappedErr := errors.New(containerBaseParseErr + containerPortErr.Error())
			fmt.Println(containerPortWrappedErr.Error())
			return containerPortWrappedErr
		}

		pair := ecs.PortMapping{
			ContainerPort: aws.Int64(containerPort),
			HostPort:      aws.Int64(hostPort),
			Protocol:      aws.String("tcp"),
		}

		definition.PortMappings = append(definition.PortMappings, &pair)
	}

	// Environment variables
	for _, envVar := range p.Environment {
		parts := strings.SplitN(envVar, "=", 2)
		pair := ecs.KeyValuePair{
			Name:  aws.String(strings.Trim(parts[0], " ")),
			Value: aws.String(strings.Trim(parts[1], " ")),
		}
		definition.Environment = append(definition.Environment, &pair)
	}

	// Secret Environment variables
	for _, envVar := range p.SecretEnvironment {
		parts := strings.SplitN(envVar, "=", 2)
		pair := ecs.KeyValuePair{}
		if len(parts) == 2 {
			// set to custom named variable
			pair.SetName(aws.StringValue(aws.String(strings.Trim(parts[0], " "))))
			pair.SetValue(aws.StringValue(aws.String(os.Getenv(strings.Trim(parts[1], " ")))))
		} else if len(parts) == 1 {
			// default to named var
			pair.SetName(aws.StringValue(aws.String(parts[0])))
			pair.SetValue(aws.StringValue(aws.String(os.Getenv(parts[0]))))
		} else {
			fmt.Println("invalid syntax in secret enironment var", envVar)
		}
		definition.Environment = append(definition.Environment, &pair)
	}

	// Environment variables from AWS Secrets manager
	for _, envVar := range p.SecretsManagerEnvironment {
		parts := strings.SplitN(envVar, "=", 2)
		pair := ecs.Secret{
			Name:      aws.String(strings.Trim(parts[0], " ")),
			ValueFrom: aws.String(strings.Trim(parts[1], " ")),
		}
		definition.Secrets = append(definition.Secrets, &pair)
	}

	// Ulimits
	for _, uLimit := range p.Ulimits {
		cleanedULimit := strings.Trim(uLimit, " ")
		parts := strings.SplitN(cleanedULimit, " ", 3)
		name := strings.Trim(parts[0], " ")
		softLimit, softLimitErr := strconv.ParseInt(parts[1], 10, 64)
		if softLimitErr != nil {
			softLimitWrappedErr := errors.New(softLimitBaseParseErr + softLimitErr.Error())
			fmt.Println(softLimitWrappedErr.Error())
			return softLimitWrappedErr
		}
		hardLimit, hardLimitErr := strconv.ParseInt(parts[2], 10, 64)
		if hardLimitErr != nil {
			hardLimitWrappedErr := errors.New(hardLimitBaseParseErr + hardLimitErr.Error())
			fmt.Println(hardLimitWrappedErr.Error())
			return hardLimitWrappedErr
		}

		pair := ecs.Ulimit{
			Name:      aws.String(name),
			HardLimit: aws.Int64(hardLimit),
			SoftLimit: aws.Int64(softLimit),
		}

		definition.Ulimits = append(definition.Ulimits, &pair)
	}

	// DockerLabels
	for _, label := range p.Labels {
		parts := strings.SplitN(label, "=", 2)
		definition.DockerLabels[strings.Trim(parts[0], " ")] = aws.String(strings.Trim(parts[1], " "))
	}

	// EntryPoint
	for _, v := range p.EntryPoint {
		var command string
		command = v
		definition.EntryPoint = append(definition.EntryPoint, &command)
	}

	// LogOptions
	if len(p.LogDriver) > 0 {
		definition.LogConfiguration = new(ecs.LogConfiguration)
		definition.LogConfiguration.LogDriver = &p.LogDriver
		if len(p.LogOptions) > 0 {
			definition.LogConfiguration.Options = make(map[string]*string)
			for _, logOption := range p.LogOptions {
				parts := strings.SplitN(logOption, "=", 2)
				logOptionKey := strings.Trim(parts[0], " ")
				logOptionValue := aws.String(strings.Trim(parts[1], " "))
				definition.LogConfiguration.Options[logOptionKey] = logOptionValue
			}
		}
	}

	// Command
	for _, command := range p.Command {
		definition.Command = append(definition.Command, &command)
	}

	if len(p.NetworkMode) == 0 {
		p.NetworkMode = "bridge"
	}

	if len(p.HealthCheckCommand) != 0 {
		healthcheck := ecs.HealthCheck{
			Command:  aws.StringSlice(p.HealthCheckCommand),
			Interval: &p.HealthCheckInterval,
			Retries:  &p.HealthCheckRetries,
			Timeout:  &p.HealthCheckTimeout,
		}
		if p.HealthCheckStartPeriod != 0 {
			healthcheck.StartPeriod = &p.HealthCheckStartPeriod
		}
		definition.HealthCheck = &healthcheck
	}

	params := &ecs.RegisterTaskDefinitionInput{
		ContainerDefinitions: []*ecs.ContainerDefinition{
			&definition,
		},
		Family:      aws.String(p.Family),
		Volumes:     volumes,
		TaskRoleArn: aws.String(p.TaskRoleArn),
		NetworkMode: aws.String(p.NetworkMode),
	}

	cleanedCompatibilities := strings.Trim(p.Compatibilities, " ")
	compatibilitySlice := strings.Split(cleanedCompatibilities, " ")

	if cleanedCompatibilities != "" && len(compatibilitySlice) != 0 {
		params.RequiresCompatibilities = aws.StringSlice(compatibilitySlice)
	}
	// placement constraints
	placementConstraints := []*ecs.TaskDefinitionPlacementConstraint{}
	if p.PlacementConstraints != "" && len(p.PlacementConstraints) != 0 {
		var placementConstraint []placementConstraintsTemplate
		constraintParsingError := json.Unmarshal([]byte(p.PlacementConstraints), &placementConstraint)
		if constraintParsingError != nil {
			constraintsParseWrappedErr := errors.New(placementConstraintsBaseParseErr + constraintParsingError.Error())
			return constraintsParseWrappedErr

		}
		for _, constraint := range placementConstraint {
			pc := ecs.TaskDefinitionPlacementConstraint{}
			// distinctInstance constraint can only be specified when launching a task or creating a service. So, currently, the only available type is memberOf
			pc.SetType(constraint.Type)
			pc.SetExpression(constraint.Expression)
			placementConstraints = append(placementConstraints, &pc)
			//params.PlacementConstraints = append(params.PlacementConstraints, &pc)
		}
		params.PlacementConstraints = placementConstraints
	}

	if len(p.TaskCPU) != 0 {
		params.Cpu = aws.String(p.TaskCPU)
	}

	if len(p.TaskMemory) != 0 {
		params.Memory = aws.String(p.TaskMemory)
	}

	if len(p.TaskExecutionRoleArn) != 0 {
		params.ExecutionRoleArn = aws.String(p.TaskExecutionRoleArn)
	}

	resp, err := svc.RegisterTaskDefinition(params)
	if err != nil {
		return err
	}

	taskDefinition := *(resp.TaskDefinition.TaskDefinitionArn)

	/// New section

	taskParams := &ecs.RunTaskInput{
		Cluster:              aws.String(p.Cluster),
		Count:                aws.Int64(p.DesiredCount),
		Group:                aws.String(p.Family),
		LaunchType:           aws.String(p.Compatibilities),
		NetworkConfiguration: p.setupServiceNetworkConfiguration(),
		//Overrides:                TODO, or not - why override container if everything defined in this run (to consider)
		//PlacementStrategy:        TODO
		//Tags:                     TODO
		TaskDefinition:       aws.String(taskDefinition), // TODO: give an option to not create a new task definition on each run, use existing one instead (to consider)
		EnableExecuteCommand: aws.Bool(p.EnableExecuteCommand),
	}

	if (p.Compatibilities == "FARGATE") && (len(p.PlatformVersion) > 0) {
		taskParams.PlatformVersion = &p.PlatformVersion
	}
	if p.PropagateTags {
		taskParams.PropagateTags = aws.String("TASK_DEFINITION")
	}

	for _, capElem := range p.CapacityProviders {
		cleanedCap := strings.Trim(capElem, " ")
		parts := strings.SplitN(cleanedCap, " ", 3)
		base, baseErr := strconv.ParseInt(parts[0], 10, 64)
		weight, weightErr := strconv.ParseInt(parts[1], 10, 64)
		if baseErr != nil {
			baseWrapperErr := errors.New(capProviderBaseParseErr + baseErr.Error())
			LogTime()
			fmt.Println(baseWrapperErr.Error())
			return baseWrapperErr
		}
		if weightErr != nil {
			weightWrappedErr := errors.New(weightParseErr + weightErr.Error())
			LogTime()
			fmt.Println(weightWrappedErr.Error())
			return weightWrappedErr
		}
		cap := &ecs.CapacityProviderStrategyItem{
			Base:             &base,
			Weight:           &weight,
			CapacityProvider: &parts[2],
		}
		taskParams.CapacityProviderStrategy = append(taskParams.CapacityProviderStrategy, cap)
	}

	// Standalone task's placementConstraints seems to be redundant if we already use them in task definition... yes/no?
	// this is bad: ecs.TaskDefinitionPlacementConstraint <> ecs.PlacementConstraint
	/* if len(placementConstraints) > 0 {
	    taskParams.PlacementConstraints = placementConstraints
	} */

	tresp, terr := svc.RunTask(taskParams)
	if terr != nil {
		return terr
	}
	LogTime()
	fmt.Println("Starting tasks:")
	fmt.Println(tresp)

	// get tasks' IDs:
	tids := []*string{}
	for _, task := range tresp.Tasks {
		tid := task.TaskArn
		tids = append(tids, tid)
	}

	describeTaskInput := &ecs.DescribeTasksInput{
		Cluster: aws.String(p.Cluster),
		Tasks:   tids,
	}

	// Wait until each task is finished (or timeout)
	//timeout := p.TaskTimeout
	timeStart := time.Now().Unix()
	timePassed := int64(0)

	taskStatus := make(map[string]string)
	finalOutput := &ecs.DescribeTasksOutput{}
	for {
		allTasksStopped := true
		tout, tterr := svc.DescribeTasks(describeTaskInput)
		if tterr != nil {
			return tterr
		}
		// Get failures
		if len(tout.Failures) > 0 {
			LogTime()
			fmt.Println("There are failures!")
			fmt.Println(tout.Failures)
			break
		}

		// Get tasks statuses
		for _, task := range tout.Tasks {
			val, exists := taskStatus[*task.TaskArn]
			if (!exists) || (val != *task.LastStatus) {
				taskStatus[*task.TaskArn] = *task.LastStatus
				LogTime()
				fmt.Println("Task: " + *task.TaskArn + "; status: " + *task.LastStatus)
			}
			if p.DontWait {
				if len(val) == 0 || (val == "PROVISIONING") || (val == "PENDING") || (val == "ACTIVATING") {
					allTasksStopped = false
				}
			} else {
				if !(val == "STOPPED") {
					allTasksStopped = false
				}
			}
		}

		if timePassed != time.Now().Unix()-timeStart {
			timePassed = time.Now().Unix() - timeStart
			if timePassed > p.TaskTimeout {
				LogTime()
				fmt.Println("TIMEOUT!")
				if p.TaskKillOnTimeout {
					fmt.Println("Stopping tasks:")
					// send kill signal to tasks
					for key := range taskStatus {
						stopTask := &ecs.StopTaskInput{
							Cluster: aws.String(p.Cluster),
							Reason:  aws.String(fmt.Sprintf("Drone's plugin timeout after %ds", timePassed)),
							Task:    &key,
						}
						out, err := svc.StopTask(stopTask)
						fmt.Println(out)
						if err != nil {
							fmt.Println(err)
						}
					}
				}
				//return errors.New(fmt.Sprintf(timeoutErr+"%ds!", timePassed))
				return fmt.Errorf(timeoutErr+"%ds!", timePassed)
			}
			// Impatience log
			if (timePassed)%10 == 0 {
				LogTime()
				fmt.Println("Still running...")
			}

		}

		if allTasksStopped {
			LogTime()
			if p.DontWait {
				fmt.Println("All tasks running!")
			} else {
				fmt.Println("All tasks stopped!")
			}
			finalOutput = tout
			break
		}

		time.Sleep(200 * time.Millisecond)
	}

	// if ignore fail, print final finalOutput
	if p.IgnoreExecutionFail {
		fmt.Println(finalOutput)
	} else if !p.DontWait {
		// Check all containers exit codes
		failedContainers := []string{}
		for _, task := range finalOutput.Tasks {
			for _, container := range task.Containers {
				if container.ExitCode == nil {
					LogTime()
					fmt.Println("Task Failed")
					fmt.Println(task)
					return fmt.Errorf(taskFailedErr + *task.StoppedReason)
				} else if *container.ExitCode != int64(0) {
					fmt.Println(container.GoString())
					failedContainers = append(failedContainers, container.GoString())
				}
			}
		}

		if len(failedContainers) > 0 {
			LogTime()
			fmt.Println("Failed containers:")
			fmt.Println(failedContainers)
			return errors.New("There are failed containers")
		}
	}

	return nil
}

// setupServiceNetworkConfiguration is used to setup the ECS service network
// configuration based on operator input.
func (p *Plugin) setupServiceNetworkConfiguration() *ecs.NetworkConfiguration {
	netConfig := ecs.NetworkConfiguration{AwsvpcConfiguration: &ecs.AwsVpcConfiguration{}}

	if p.NetworkMode != ecs.NetworkModeAwsvpc {
		return nil
	}

	if len(p.ServiceNetworkAssignPublicIP) != 0 {
		netConfig.AwsvpcConfiguration.SetAssignPublicIp(p.ServiceNetworkAssignPublicIP)
	}

	if len(p.ServiceNetworkSubnets) > 0 {
		netConfig.AwsvpcConfiguration.SetSubnets(aws.StringSlice(p.ServiceNetworkSubnets))
	}

	if len(p.ServiceNetworkSecurityGroups) > 0 {
		netConfig.AwsvpcConfiguration.SetSecurityGroups(aws.StringSlice(p.ServiceNetworkSecurityGroups))
	}

	return &netConfig
}
