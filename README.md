# Build Update Release Pipeline (BURP)

# Business Problem

Big Bang releases are hard to develop, test, verify, and operate. Established DevOps principles indicate that teams should work in small batches and deploy as frequently as possible. Slow, manual release processes result in fewer deployments, which lead to even more troublesome deployments. Manual releases can introduce a plethora of problems. It is simply a realistic notion that we, as human beings, can't complete the same task 100 times and do it the same way each time. Combining the work of multiple developers is also a challenge. Software systems are complex, and an apparently simple, self-contained change to a single file can easily have unintended consequences which compromise the correctness of the system. 

# Business Value

Continuous integration and continuous deployment (CI/CD) pipelines are a practice focused on improving software delivery throughout the software development life cycle via automation. By automating CI/CD through development, testing, production, and monitoring phases of the software development lifecycle, organizations can develop higher quality code, faster. Although it’s possible to manually execute each of the steps of a CI/CD pipeline, the true value of CI/CD pipelines is realized through automation.
- Accelerated Delivery: Drive business value inherent in new software releases to customers more quickly. 
- Improved productivity and efficiency: Significant time savings for developers, testers, operations engineers, etc. through automation.
- Reliable releases: With more frequent releases, the number of code changes in each release decreases. This makes finding and fixing any problems that do occur easier, reducing the time in which they have an impact.


# Asset Description 

## try this

This pipeline design is a highly flexible templated and componentized framework that has become a foundation of Microsoft enterprise solutions development. Leverage this release automation approach to drive work consistency and enable comprehensive, high-quality accelerated releases for complex development engagements. 

Asset Details (Jim)
Nested strategy approach
The standard reference pipeline is ---
Stage files
Within state files jobs
Within Jobs include collections of tasks….