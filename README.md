# Release Automation & Development [RAD]

This repository contains a Microsoft open source CI/CD framework reference for Azure DevOps pipelines and GitHub Actions.  These reference pipelines use a template and componentized model to enable teams to quickly create flexible and scalable enterprise ready pipelines.

# Business Problem

Big Bang releases are hard to develop, test, verify, and operate. Established DevOps principles indicate that teams should work in small batches and deploy as frequently as possible. Slow, manual release processes result in fewer deployments, which lead to even more troublesome deployments. Manual releases can introduce a plethora of problems. It is simply a realistic notion that we, as human beings, can't complete the same task 100 times and do it the same way each time. Combining the work of multiple developers is also a challenge. Software systems are complex, and an apparently simple, self-contained change to a single file can easily have unintended consequences which compromise the correctness of the system. 

# Business Value

Continuous integration and continuous deployment (CI/CD) pipelines are a practice focused on improving software delivery throughout the software development life cycle via automation. By automating CI/CD through development, testing, production, and monitoring phases of the software development lifecycle, organizations can develop higher quality code, faster. Although it’s possible to manually execute each of the steps of a CI/CD pipeline, the true value of CI/CD pipelines is realized through automation.
- Accelerated Delivery: Drive business value inherent in new software releases to customers more quickly. 
- Improved productivity and efficiency: Significant time savings for developers, testers, operations engineers, etc. through automation.
- Reliable releases: With more frequent releases, the number of code changes in each release decreases. This makes finding and fixing any problems that do occur easier, reducing the time in which they have an impact.


# Azure DevOps Asset Description 

The Azure DevOps pipeline design is a highly flexible templated and componentized framework that has become a foundation of Microsoft enterprise solutions development. Leverage this release automation approach to drive work consistency and enable comprehensive, high-quality accelerated releases for complex development engagements. The Azure DevOps pipeline implementation can be found in the .ado folder off the root of the project.

## Parent Pipeline

The pipeline is implemented with a single parent pipeline that define a set of stages.  Each stage in the parent pipeline references a specific stage file that is passed properties from the parent.  The parent pipeline contains only input parameters, variables file references, and the defined stages.

## Stages

Each stage is implemented with its own stage file located under the .ado/Template/Stage directory.  Each stage file receives a set of properties from the parent template that defines each stage.  The stage file references a common Job template file, which is passed a set of parameters that includes stepList parameter.  The stepList parameter is a collection of yaml files that contain the Azure DevOps tasks that will be run in each job.  The StepList allows pipeline developers to organize the various tasks that need to be performed into a logical grouping (within the same yaml file) to make development and support much easier than if everything was located in a single pipeline file.

## Job Template

There are two standard job templates that are referenced in the stages file and which are passed parameters for processing.  These include the template for a standard Azure DevOps Job and the other is for a standard Azure DevOps Deployment.  The deployment template should be used when the developer needs to use Azure deployment Environments and Approval Gates.

# GitHub Actions Asset

The GitHub Actions pipeline is in development and will be located in the .github folder.  
