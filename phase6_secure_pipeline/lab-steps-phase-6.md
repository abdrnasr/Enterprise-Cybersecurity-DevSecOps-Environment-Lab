# GitLab Runner Reconfiguration

We begin reconfiguring the `GitLab Runner` to use a [`docker`](https://docs.gitlab.com/runner/executors/docker/) executor rather than a [`shell`](https://docs.gitlab.com/runner/executors/shell/) executor. This is to avoid installing the tools required for the CI/CD pipeline on the system and to simplify the CI/CD pipeline configuration. Rather, we will choose the most appropriate images for each stage.

More information about the `docker` runner: https://docs.gitlab.com/runner/executors/docker/

## Create & Register a New Runner in GitLab

1. Begin with creating a new Runner in `GitLab`.

<p align="center">
  <img width=60% src="images/GLab_New_Runner.png">
</p>

2. Then, on the `CI/CD VM`, stop the existing runner:

```bash
sudo systemctl stop gitlab-runner.service
```

3. Next, execute the command that `GitLab` provided, along with the secret. Ensure you run the command with `sudo`.

```bash
cid@cid:~$ sudo gitlab-runner register  --url http://192.168.20.4  --token <GitLab_Token>
[sudo] password for cid:
Runtime platform                                    arch=amd64 os=linux pid=6029 revision=5a021a1c version=18.3.1
Running in system-mode.

Enter the GitLab instance URL (for example, https://gitlab.com/):
[http://192.168.20.4]: # Keep it empty, as the value is already correct
Verifying runner... is valid                        correlation_id=$$$$$$$$$$$$ runner=M7sXVzdxJ
Enter a name for the runner. This is stored only in the local config.toml file:
[cid]: docker_runner # Use any name here
Enter an executor: custom, shell, ssh, parallels, docker, docker-windows, docker+machine, kubernetes, virtualbox, docker-autoscaler, instance:
docker # You must use docker here
Enter the default Docker image (for example, ruby:3.3):
node:lts # I decided to use node:lts as a base image for the tasks that we do not specify an image for
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!

Configuration (with the authentication token) was saved in "/etc/gitlab-runner/config.toml"
```

4. With this done, the new runner should appear on `GitLab`.

<p align="center">
  <img src="images/GLab_New_Runner_Running.png">
</p>

**If you encountered any problems with the runner being offline as above, chances are that you have not use `sudo` with the registration above.**

<p align="center">
  <img src="images/GLab_Runner_Actually_Running.png">
</p>

If the runner appears as `Online`, then we are ready to proceed configuring the pipeline.

---

# Describing & Setting Up `GitLab` for The Pipeline

In order to build the pipeline, we need to describe what are the tasks that the pipeline will do, and prepare a `GitLab` project where the pipeline will exist.

| Stage            | Objective                                      | Tools/Implementation   |
|------------------|------------------------------------------------|------------------------|
| 1. **Secrets**   | Detect exposed secrets in codebase             | `Gitleaks`               |
| 2. **Dependency**| Scan npm packages for known security issues    | `npm audit`             |
| 3. **Test**      | Execute unit tests with coverage               | `Vitest`                 |
| 4. **SAST**      | Static code analysis for vulnerabilities       | `SonarQube`, `SonarScanner CLI` |
| 5. **Build & Release** | Install dependencies, compile Next.js app, and deliver it   | `npm ci`, `npm run build`, `rsync`, `ssh` |
| 6. **DAST**      | Perform Dynamic Testing and Scanning       | `Playwright`, `OWASP ZAP` |
| 7. **Deploy**    | Transfer and start app on internal server      | `ssh`            |

0. First, the pipeline will clone the `git` repository of the [chat-app](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM) project. Since the repository will be hosted in `GitLab`, this happens automatically whenever new changes are pushed. Each job in the pipeline gets its own working copy of the codebase (including all the files in the repo).

1. The pipeline starts with a **Secrets scan**. Using `Gitleaks`, we check the repository for any accidentally committed secrets (tokens, passwords, API keys, etc.). This does not prevent secrets from being pushed in the first place, but it alerts us immediately if something slipped through. Ideally, `Gitleaks` should also run locally on developer laptops (pre-commit/pre-push), but having it here ensures we at least detect secrets inside the repo.

2. We then perform a **Dependency scan**. Here, we run `npm audit` to compare our project’s dependency tree (`package-lock.json` and installed packages) against known security advisories. This identifies vulnerable third-party libraries.

3. After this, we run the **Test stage**. Unit tests are executed using `Vitest`, with coverage enabled. These tests verify that our application's logic works correctly and catch regressions early.

4. Moving forward, the **SAST stage** analyzes the source code using `SonarQube`. This static analysis highlights vulnerabilities, code smells, and maintainability issues. It uses the source files and type information from dependencies.

5. Next, we enter the **Build stage**. In this stage, we run `npm ci` to install dependencies cleanly and reproducibly, followed immediately by `npm run build` to compile the `Next.js` application. This produces many artifacts required for runtime, such as `node_modules/` and `.next/` output. These files are then delivered to the application server using `rsync`. Finally, a test instance is run so that we can perform DAST against it.

6. Next comes DAST with `OWASP ZAP` baseline. In this stage, we target the test instance of the app located on http://192.168.20.2:3005, which performs various passive scans against it. In such a test, it is not recommended to use the actual instances for your services. For our case, we use the existing `MySQL` and `Keycloak` instances, since it will consume a lot of system resources. To stay safe, we don’t use the production DB or production `Keycloak` realm: instead we configure a dedicated test database schema and a test realm/client in `Keycloak`. This gives us a realistic environment to scan without endangering production data. ZAP then crawls and passively tests the running app for vulnerabilities.

7. Finally, if all stages succeed, we reach the **Deploy stage**. At this point, we simply tell the `APP VM` to run the latest version of the app. All the required environment variables will already be ready on the `APP VM` and stored in a secure folder, protected by Linux permissions. Finally, since we will use a blue/green strategy, `Nginx` will be reconfigured to point to the correct destination.


## Approach

The way we are going to approach building this pipeline is step by step: we start by implementing the **Secrets scan** stage and testing it. If everything works as expected, we move on to the next stage. After adding the new stage, we test again to make sure it runs correctly. We continue this process until all stages are in place. With this strategy, we incrementally build and validate our `.gitlab-ci.yml` file. This approach ensures that we don’t push forward to later stages only to discover issues in earlier ones.

A point to notice here is that we should always strive to place quicker stages and security checks at the beginning of the pipeline to avoid wasting resources. For example, if we put the DAST stage early in the pipeline, it will take around a full minute to complete the [`OWASP ZAP Baseline`](https://www.zaproxy.org/docs/docker/baseline-scan/) scan. If a secret had already been leaked, we would only discover it after that one-minute scan had finished. While one minute might not seem like a big deal in this case, more intensive scans and processes can take significantly longer. That’s why it is important to prioritize faster checks first—so we can fail fast, save time, and conserve resources.

## Test Scenarios

Along the stages, we will simulate several scenarios to test the effectiveness of the pipeline. For instance,

| Scenario                                        | Pipeline Reaction                            |
|-------------------------------------------------|----------------------------------------------|
| Introduce a secret (e.g., `Keycloak` Client key)  | blocked by `gitleaks`                        |
| Add a vulnerable dependency                       | flagged by `npm audit`                       |
| Fail a `Vitest` test case                         | flagged by `Vitest`                          |
| `SonarQube` `Quality Gate` Failure                  | flagged by `SAST`                            |

There are various scenarios we could explore here, but the point is not to cover every possible case. Instead, we will focus on a small set of meaningful examples that show how the pipeline reacts to common failure conditions. This way, we validate that the pipeline is doing its job without over-complicating the pipeline process.

## Project Setup

Before we start building the pipeline, we need to create a new `GitLab` project and upload our code files to it.

<p align="center">
  <img width=80% src="images/GLab_CreateProject.png">
</p>

We do not choose the `Enable (SAST)` or `Enable Secrets Detection`, because we will be implementing them in our custom-made stages as a part of the pipeline.

<p align="center">
  <img width=80% src="images/GLab_Project_Empty.png">
</p>

Now that the project is created, we need to push our source code to the `GitLab` repository. On the same machine where you set up the `SSH to GitLab` tunnel, open your favorite IDE, choose a working directory to place the code in, and open a terminal window. 

<p align="center">
  <img width=80% src="images/Admin_VS_Project.png">
</p>

First, we clone the [`chat-app`](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM) project.

```bash
# Clone
git clone https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM.git
# Navigate into the repo's root directory
cd Chat-App-with-Keycloak-IAM
# Add a new remote called gitlab. This remote uses the SSH proxy as we configured in phase 5.
git remote add gitlab gitlab:root/chat-app-pipeline.git
```

We then check the validity of the remote.

```bash
# This will list the available remotes
git remote -v
# We then test the connectivity
git ls-remote gitlab
# If it works, it will return the refs (branches, tags) available on the remote.
```

<p align="center">
  <img src="images/Admin_remote.png">
</p>

<p align="center">
  <img src="images/Admin_Git_Test_Connection.png">
</p>

Finally, we need to push the code to the `GitLab` repo, which we can do with `git merge`.

```bash
git fetch
git merge --allow-unrelated-histories gitlab/main
```

You will then be asked to resolve the conflicts. Resolve them (I chose to keep both READMEs in one file) and execute the following commands:

```bash
git add .
git commit
git push -u gitlab main
```

With all of this done, the chat-app code is available now on `GitLab`. 

<p align="center">
  <img width=80% src="images/GLab_Code.png">
</p>

Now, we can start working on the pipeline itself by configuring the `.gitlab-ci.yml` file. Editing this file can either be done in your IDE, or directly in GitLab's Pipeline Editor.

<p align="center">
  <img width=80% src="images/GLab_Pipeline_Editor.png">
</p>

We will be using the IDE, since we need edit/change code files in addition to the `.gitlab-ci.yml`.

---

# Building The Pipeline

As we described, the pipeline comprises many stages and we will build it incrementally. Under [`/files`](./files), you will find the `gitlab-ci.yml` for each stage. The file will get incrementally big, so small snippets may be displayed here. If you would like to use it, be sure to rename the files to `gitlab-ci.yml` before pushing to `GitLab`. 

## Secret Scanning

We begin with the secret scanning pipeline. First, create the `.gitlab-ci.yml` in the root directory of the local `git` repo. Inside, this file the following configuration should be used:

```yaml
stages:
  - secrets-scan

variables:
  GITLEAKS_REPORT: "gitleaks-report.json"

gitleaks_scan:
  stage: secrets-scan
  image:
    name: zricethezav/gitleaks:v8.18.4 
    entrypoint: [""]   
  rules:
    # Run on all events on the default branch
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    # Basic scan of the repository working tree
    - gitleaks detect --source . --report-format json --report-path "$GITLEAKS_REPORT" --exit-code 1
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - $GITLEAKS_REPORT
```

The above first stage of the pipeline basically downloads the `zricethezav/gitleaks:v8.18.4` image and analyzes all the code files present in the repo. `GitLeaks` generates a report file at `$GITLEAKS_REPORT"`. If a secret was detected, `GitLeaks` exists with code 1, which would fail the pipeline from continuing. Regardless of the pipeline's outcome, the report is `always` generated and available for our review for 7 days, after which it will be deleted.

In addition to this file, we add another file containing secrets that must not be present inside the repository. Create a file called `sec.env` and place these two secrets in it:

```ini
NEXTAUTH_SECRET=XMOwAut61xtw3AIOkuzG0cORgjkwkLZg
SEEDING_SECRET=1axa73PWpI6vxuLrjkWUJ27PUxfgedp7
```

Those values were generated by https://randomkeygen.com/, and they are to be disposed. These are values only used for testing the detection of secrets stage. The reason we chose `NEXTAUTH_SECRET` & `SEEDING_SECRET` is because these are [relevant variables](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM?tab=readme-ov-file#app-setup) that may appear in our chat-app repository. Other relevant variables specific to this chat-app would be `DATABASE_URL` & `KEYCLOAK_CLIENT_SECRET`.

**All the environment variables for the chat-app: https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM?tab=readme-ov-file#app-setup**

Once these two files are added, add, commit, and push these changes to the repository.

### Detection

Running the pipeline, we see that it has successfully detected the secrets that we have added.

<p align="center">
  <img src="images/Glab_Secret_Detected.png">
</p>

On the right side of the window, you will a `"Job artifacts"` section. This will contain the scan result, so we can download it and have a look at the detections.

The JSON file generated: [gitleaks-report.json](./result/gitleaks-report.json).

`Gitleaks` analyzed the repository commits and found the two secrets that we generated as a test. The secrets it found where located in the `sec.env` folder; the file we intentionally created with secrets. Along with the secrets is the commits these secrets were found in, so we need to deal with these exposed secrets.

### Secrets Removal

Before we proceed, we need to delete these secrets from the repository to prevent `Gitleaks` from flagging them. If we do not do this, the pipeline will not proceed to the next stages. Secrets removal is a tedious process and is prone to mistakes. Thus, you should have a safe copy of the repository and clean the repository from the secrets.

The steps that was followed here is that the commits that were flagged by `GitLeaks` were entirely deleted. For this, the `rebase` functionality was used to delete these two commits. After deleting the flagged commits, we need to ensure that `GitLab` does not reuse a cached copy of the repo. This is because the cached copy may contain the `sec.env`; the file that contained the secrets. So, we update our `.gitlab-ci.yml` file.

```yml
stages:
  - secrets-scan

variables:
  GITLEAKS_REPORT: "gitleaks-report.json"
  #### NEWLY ADDED
  GIT_STRATEGY: "clone"        # always do a fresh clone (no repo cache reuse)
  GIT_CHECKOUT: "true"         # ensure working tree is checked out
  GIT_DEPTH: "0"               # full history (set to "1" if you only need the tip)
  GIT_CLEAN_FLAGS: "-ffdx"     # wipe untracked + ignored files before checkout
  #### NEWLY ADDED

gitleaks_scan:
  stage: secrets-scan
  image:
    name: zricethezav/gitleaks:v8.18.4 
    entrypoint: [""]   
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - gitleaks detect --source . --report-format json --report-path "$GITLEAKS_REPORT" --exit-code 1
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - $GITLEAKS_REPORT
```

Those variables that we have defined instruct `GitLab` to use a clean copy of the repo, and to delete any file inside the local repo version. With that, we need to force-push the changes. However, `GitLab` would not allow this behavior by default. 

On `GitLab`, navigate to `project settings -> Repository -> Protected branches`. 

<p align="center">
  <img width=70% src="images/GLab_UnProtectBranchForPush.png">
</p>

Here, you can activate `Allowed to force push` temporarily, and then execute a `push` command. After pushing is complete, you should revert this option back to its original value.

```bash
git push gitlab --force-with-lease
```
<p align="center">
  <img width=80% src="images/Glab_Success_GitLeaks.png">
</p>

If this is done correctly, the pipeline should succeed, and no secrets should be found.

### Handling Secret Leakage

When we discover that a secret such as an API key, password, or token has leaked, we must treat it as compromised right away. We revoke or disable the exposed key from the system where it was issued, then generate a new one to replace it. We update our applications, configuration files, or environment variables with the new secret and test to confirm everything works correctly. Next, we remove the leaked secret from our codebase and its history, and make sure all team members refresh their local copies. Since a leaked secret may already be in use by attackers, we always prioritize immediate rotation and revocation. In other words, removing the secrets from the codebase is rather a task that is done towards the end of a **secret leakage incident**, and we should prioritize the revocation and rotation of new secrets first.

---

## Dependency Scan

Next, we add the dependency check phase into the pipeline. Before we do this, we introduce a deliberately vulnerable package using: 

```bash
npm install --save-dev serialize-javascript@2.1.0
```
Executing this command adds this package to the `package-lock.json` and `package.json` files. These are the two files that are mainly utilized by the `npm audit` command to scan for vulnerable dependencies. 

Immediately after downloading this package, you will get the following warning:

<p align="center">
  <img src="images/Admin_Audit_Warning.png">
</p>

Thus, executing the following `npm audit --audit-level=high` command must **not** exit with **code 0**.

```bat
# Run the audit command, setting "high" as the failure threshold
npm audit --audit-level=high

# Windows BAT Command
# If a high/critical-severity vulnerability is detected, then the exit code will be 1
echo %ERRORLEVEL% 
```

<p align="center">
  <img src="images/Glab_Vulnerable_Dependency.png">
</p>

As you can see, the local `npm audit` command works correctly by exiting with exit code 1. Now, we would like to test this capability in the pipeline itself. 

### Adding The Dependency Scanning Stage in `.gitlab-ci.yml`

Here is the new `.gitlab-ci.yml` file.

```yml
stages:
  - secrets-scan
  - dependency-scan # New Stage Added

################################
### Remaining Stages Omitted ###
################################

# New Stage Added
dependency_scan:
  stage: dependency-scan
  image: node:22-alpine
  before_script:
    - npm ci --ignore-scripts
  script:
    # Fail if High or Critical vulns found
    - npm audit --audit-level=high
  artifacts:
    when: always
    paths:
       - npm-audit.json
    expire_in: 7 days
  after_script:
    # Since the initial scan can fail, we need to do another scan that does not fail. 
    # This scan will produce an output file that we can persist
    - npm audit --json > npm-audit.json || true 
```
**Full File: [2-dependency-test.gitlab-ci.yml](./files/2-dependency-test.gitlab-ci.yml)**

The pipeline stage here is straightforward. We simply use the same `npm audit` command in the pipeline. If a high/critical-severity vulnerability is detected, the pipeline fails.

### Testing Detection Stage

Pushing the changes to the repo with the vulnerable package, the pipeline should run and it should fail.

<p align="center">
  <img width=80% src="images/GLab_Vulnerable_Failure.png">
</p>

JSON Audit Output: [npm-audit](./result/npm-audit.json)

The reason for the failure is as we have discussed, a high-severity vulnerability was detected and the scan exited with code 1, which causes the pipeline to fail.

### Removing The Faulty Package

The package that caused the failure is the `serialize-javascript` package. We do not use it in our code, so we can safely remove it.

```bash
npm uninstall --save-dev serialize-javascript
```

After removing it, the high-severity vulnerability should disappear from the log.

<p align="center">
  <img src="images/Admin_No_High_Sev.png">
</p>

With this package removed, pushing the new changes to `GitLab` should succeed.

### Successful Pipeline Result Interpretation

<p align="center">
  <img width=80% src="images/Glab_Dependency_Check_Success.png">
</p>

As the image shows, the pipeline has succeeded. While there is a `medium`-severity vulnerability, the threshold that we have set for failure is `high`. Thus, the pipeline still succeeds.

---


## Unit Testing and Coverage Reporting

Next, we move to the **Unit Testing** stage. In this stage, we use `Vitest` to write our unit tests. In addition to unit testing, `Vitest` will be configured to run coverage test. In a single command, `Vitest` will perform both tests and only succeed when both tests do.

Initially, the [chat-app](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM) did not have any unit tests and `Vitest` was not configured. Later, I configured `Vitest` and wrote some test with it.

<p align="center">
  <img src="images/Admin_vi_test_added.png">
</p>

Here, we added a new stage to the pipeline in the `.gitlab-ci.yml` file.

```yml
stages:
  - secrets-scan
  - dependency-scan
  - test-coverage # NEW STAGE ADDED

gitleaks_scan:
  rules:
    - when: never ##### DISABLED #####

dependency_scan:
  rules:
    - when: never ##### DISABLED #####

#################
### New Stage ###
#################
test-coverage:
  image: node:lts
  stage: test-coverage

  cache:
    key:
      files:
        - package-lock.json
    paths:
      - .npm/
      - .next/
    policy: pull-push

  variables:
    NPM_CONFIG_CACHE: "$CI_PROJECT_DIR/.npm"

  before_script:
    - npm ci

  script:
    - npm run coverage:json

  artifacts:
    when: on_success
    expire_in: 1 week
    paths:
      - coverage/coverage-final.json
```
**Full File: [3-unit-coverage-test.gitlab-ci.yml](./files/3-unit-coverage-test.gitlab-ci.yml)**

**In the above config file, the first two stages were disabled to immediately execute the new stage without waiting.**

This pipeline stage is straightforward, the dependencies are installed using `npm ci`. Then both coverage and unit tests are executed with the `npm run coverage:json`. On success, a report is produced and placed at `coverage/coverage-final.json`. The reports are preserved using the artifact directive.

Before pushing the changes, see the three tests shown next.

### Test 1: Full Coverage and Tests Pass

The default state of the uploaded repository should allow the tests to pass. You can verify this by executing:

```bash
# Install the packages needed by the project
npm install
# Run the coverage test
npm run coverage
```

<p align="center">
  <img src="images/Admin_Full_Coverage.png">
</p>

The image shows the success of the unit tests and that all of the included code parts are totally covered. Pushing the current state to `GitLab` should result in a success.

<p align="center">
  <img width=80% src="images/GLab_Coverage_Success.png">
</p>

### Test 2: Failure in a Unit Test

Another test scenario to cover is when a unit test fails. In this case, the pipeline must not continue. For this, I have prepared a test case that is intentionally made to fail. This can be found in the `chat-app-pipeline\test\lib\utils.server.test.ts` file of the [chat-app](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM) at the end of the file.

```typescript
describe("safeEqual", () => {
  // Other tests here

  // Test case to uncomment
  // it("A test made to fail intentionally", () => {
  //   expect(safeEqual("", "")).toBe(false);
  // });
});
```

To include this test case, uncomment it under the test file. The mentioned function `safeEqual("","")` securely compares two strings while preventing against [string-comparison timing attack](https://sqreen.github.io/DevelopersSecurityBestPractices/timing-attack/python). In the above case, it must return `true`. However, we intentionally wrote that the outcome is `false`. This will cause the unit test to fail.

This can be tested locally as follows:

```bash
npm run test
```

<p align="center">
  <img src="images/Admin_Unit_Test_Fail.png">
</p>

As you can see, the test failed locally. Pushing the current state of the code should also cause the pipeline to fail.

<p align="center">
  <img src="images/GLab_Bad_Unit_Test.png">
</p>

As expected, the pipeline failed because of the faulty unit test.

**IMPORTANT: Before continuing, ensure you remove/comment the faulty test.**

### Test 3: Coverage Threshold Not Exceeded

Another important scenario is when the coverage of the tests does not meet the set threshold. Under the `vitest.config.mts` file, four thresholds are defined.

```typescript

export default defineConfig({
  test: {
    coverage:{
      exclude: [
        // exclude all visual sub-components
        "app/components/**", // Comment this to fail the test
      ],
      // Uncomment this to set failure thresholds
      thresholds: {  
        lines: 90,
        functions: 90,
        branches: 85,
        statements: 90
      }
    },
  },  
})
```

The above configuration means the following:

|Threshold|Explanation| Example|
|---------|---| ---|
| `lines: 90`|The minimum percentage of lines of code that must be executed by tests.| if set to 90, then at least 90% of all lines in the project must be covered by tests.|
| `functions: 90`|The minimum percentage of functions (methods) that must be called by tests.| if you have 100 functions across your codebase, at least 90 must be exercised in tests.|
| `branches: 85`|The minimum percentage of branches in control structures (if/else, switch, ternary, etc.) that must be executed. This ensures you test different paths in the logic, not just one route through the code. | For instance, both the if and the else should be covered.|
| `statements: 90`| The minimum percentage of all executable statements (a bit broader than just lines) that must be run during tests. Sometimes multiple statements live on one line, so this metric can differ slightly from lines.| If you had 100 statements, and you tested 90, this metric will be 90. |

With our current setup, the coverage is 100%. To reduce the coverage, you could comment the following:

```typescript
      exclude: [
        // exclude all visual sub-components
        "app/components/**", // Comment this to fail the test
      ],
```

Commenting this line adds new files to the coverage test. However, no test cases were written for these files, so they will reduce the percentage of coverage.

Testing the coverage locally can be done with:

```bash
npm run coverage
```
<p align="center">
  <img height=500 src="images/Admin_Low_Coverage_Local.png">
</p>

The statement and line coverages did not meet the threshold, so an error is raised. Pushing this to `GitLab` should cause the pipeline to fail.

<p align="center">
  <img height=500 src="images/GLab_Fail_Coverage.png">
</p>

### Initial State Recovery

Before you continue to the next stage, ensure that you revert the changes that we have made to prevent the pipeline from failing and not continuing to the next stage.

To verify that your changes were correctly reverted, check with the following command:

```bash
npm run coverage
```

<p align="center">
  <img width=70% src="images/Admin_Full_Coverage.png">
</p>

This command should not display any problems.

<p align="center">
  <img width=70% src="images/GLab_Post_Test_Recovered.png">
</p>

### Coverage Report

If the test **succeeds** a JSON coverage report is produced, which can be viewed and analyzed.

<p align="center">
  <img width=70% src="images/GLab_Artifact_Download.png">
</p>

Full Report: [coverage-final.json](result/coverage-final.json)

### All Performed Tests

The following image summarizes the tests we performed:

<p align="center">
  <img width=70% src="images/GLab_All_Test_Pipelines.png">
</p>

---

## Static Application Security Testing (SAST)

Next, we move to the SAST stage. In this stage, we use `SonarQube` to analyze the codebase statically and produce quality and security reports. Before we are able to run scans, we have set up a `SonarQube` server. This server will store the analysis results for our review. 

### SonarQube Server Setup

We will use `Docker` to run `SonarQube`. `SonarQube` also requires a database to run. A `docker-compose.yml` was provided that contains two images,`SonarQube` and `PostgreSQL`. In addition to the compose file, there is an SQL script file. This file initializes the `PostgreSQL` database.

Inside the `CI/CD VM`, you should structure the files as follows:

```bash
sonarqube/
├── docker-compose.yml
└── initdb/
    └── 01-sonarqube.sql
```
Those files are available under [sonarqube](./sonarqube/). Be sure to position them as displayed (relatively). Those files also contain credentials for the database users. You may want to change them if you need.

Then on the terminal window, position yourself inside the **sonarqube** folder. Then you execute the following command:

```bash
docker compose up -d
```

<p align="center">
  <img width=700 src="images/CID_SQ_UP.png">
</p>

This should take a few minutes to set up `SonarQube` and its database.

### Accessing SonarQube

To access `SonarQube`, you need to use the `DMZ VM` for tunneling. We have done this before to access `GitLab`. So, from the same browser where you are accessing `GitLab`, access `SonarQube` at http://192.168.20.4:9000.

<p align="center">
  <img width=700 src="images/Admin_SQ_Access.png">
</p>

The default credentials are:
```ini
username: admin
password: admin
```
You will be prompted to change the default password immediately after login. After Changing the password you will be able to see the homepage of the app:

<p align="center">
  <img width=700 src="images/Admin_SQ_Homepage.png">
</p>

### SonarQube Project Setup

Next, we set up the integration between `SonarQube ` and the `GitLab` API.

1. Create a new Personal Access Token (PAT) with `API` access permission included. This can be found under `User Settings -> Access Tokens`.

<p align="center">
  <img width=700 src="images/GLab_PAM_Token_Name.png">
</p>

Include the required permission:

<p align="center">
  <img width=800 src="images/GLab_PAM_Permission.png">
</p>

This will generate the Token which will be used in `SonarQube`.

<p align="center">
  <img width=800 src="images/GLab_PAM_Generated.png">
</p>

2. Visit `SonarQube` at http://192.168.20.4:9000. There, click on `Import from GitLab`.

<p align="center">
  <img height=500 src="images/SQ_Glab_Config.png">
</p>

- You will be asked to enter 3 values.

```yaml
# This can have any name
Configuration name: Chat-App-Scan 
# If you environment's setup is similar to mine, you should use this value
GitLab API URL: http://192.168.20.4/api/v4 
# The token that gitlab generated in the last step
Personal Access Token: <Whatever_GitLab_Generated> 
```
- After filling these values, click on `Save configuration`.

3. You will be presented with the list of projects available. Choose the project with the chat-app code. For my case, this is the  `chat-app-pipeline`. 

<p align="center">
  <img height=300 src="images/SQ_Choose_GLAB_Project.png">
</p>

- Press on `import`.

4. Choose the baseline strategy for the project. The default works well here.

<p align="center">
  <img height=450 src="images/SQ_GLab_Clean_Project.png">
</p>

5. Next, we are then asked to define two environment variables in the CI/CD pipeline.

<p align="center">
  <img  src="images/SQ_Env_Desc.png">
</p>

The `SONAR_TOKEN` must be generated by pressing on the `Generate` button. 

<p align="center">
  <img  src="images/SQ_Generate_Token.png">
</p>

```ini
SONAR_TOKEN=<Token_Generated_By_SonarQube>
SONAR_HOST_URL=http://192.168.20.4:9000
```

These variables must be added to the project variables through `Settings > CI/CD > Variables`.

<p align="center">
  <img src="images/GLab_CI_Variable.png">
</p>

6. Under the root of the chat-app project, create a new file named `sonar-project.properties`. The content of this file should be:

```ini
# This value will be different for you. Check the code snippet provided by SonarQube
sonar.projectKey=root_chat-app-pipeline_3a9cd35d-70ff-4bc0-b2a0-56436b6e66ec
sonar.qualitygate.wait=true

# Add the coverage file. Added later
# sonar.javascript.lcov.reportPaths=./coverage/lcov.info

# Only analyze code inside app/ as "sources"
sonar.sources=app,lib

# Tests live under test/
sonar.tests=test
sonar.test.inclusions=test/**/*.{test,spec}.{ts,tsx,js,jsx}
```

7. Finally, we are given the code snippet that we should use for the `GitLab` stage in the `.gitlab-ci.yml` file. 

```yml
stages:
  - secrets-scan
  - dependency-scan
  - test-coverage
  - sast-scan # New Stage Added

variables:
  GITLEAKS_REPORT: "gitleaks-report.json"
  GIT_STRATEGY: "clone"        # always do a fresh clone (no repo cache reuse)
  GIT_CHECKOUT: "true"         # ensure working tree is checked out
  GIT_DEPTH: "0"               # full history (set to "1" if you only need the tip)
  GIT_CLEAN_FLAGS: "-ffdx"     # wipe untracked + ignored files before checkout
  # New Variable Added
  SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"  # Defines the location of the analysis task cache

gitleaks_scan:  
  rules:
    - when: never ##### DISABLED #####

dependency_scan:
  rules:
    - when: never ##### DISABLED #####

test-coverage:
  rules:
    - when: never ##### DISABLED #####

### New Stage ###
build-sonar:
  stage: sast-scan
  image: 
    name: sonarsource/sonar-scanner-cli:11
    entrypoint: [""]
  cache:
    policy: pull-push
    key: "sonar-cache-$CI_COMMIT_REF_SLUG"
    paths:
      - "${SONAR_USER_HOME}/cache"
      - sonar-scanner/
      
  script: 
  - sonar-scanner -Dsonar.host.url="${SONAR_HOST_URL}"
  allow_failure: true
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
    - if: $CI_COMMIT_BRANCH == 'master'
    - if: $CI_COMMIT_BRANCH == 'main'
    - if: $CI_COMMIT_BRANCH == 'develop'
```

8. Lastly, you add, commit, and push the code to `GitLab` repo. The pipeline should succeed regardless of the scan result.

<p align="center">
  <img width="80%" src="images/GLab_SAST_Success.png">
</p>

### Viewing The SAST Report

On the output log, you should see a link which leads you to the report on `SonarQube` website.

<p align="center">
  <img width="80%" src="images/GLab_SonarQube_SuccessReport.png">
</p>

On this page, you will see a summary of the SAST scan.

<p align="center">
  <img width="80%" src="images/SQ_Success_Test_Initial.png">
</p>

Each of these detections correlate to a possible problem in the codebase. For example, one `security hotspot` is about a possible SQL Injection through a database query.

<p align="center">
  <img width="80%" src="images/SQ_SQL_Vulnerablity.png">
</p>

However, this is not a problem here, simply because that this query does not take any input from the user. That is, the query is static (does not change) and not controlled by the user. So, an `SQL Injection` is impossible here.

Thus, for each of the reported problems, we can systematically look at each of them and resolve them if possible.

### Coverage Report Inclusion

As you may have noticed in the earlier image, the coverage in the report is displayed as 0%. This is because `SonarQube` requires a coverage report to be fed into it. In the unit testing and coverage stage, we have added the capability for `Vitest` to produce a JSON report. Although, JSON report are brilliant for Web APIs, they do not directly work with `SonarQube`. `Vitest` offers another coverage reporting format, which is called `lcov`. This format is accepted by `SonarQube`, so we will use it here.

1. Open the file `vitest.config.mts` in the code repository and add `lcov` as a reporting format.
```typescript
//...
export default defineConfig({
  test: {
    coverage:{
      provider: 'v8',
      // This tells Vitest to produce an lcov report too
      reporter: ['text', 'json', 'html','lcov'], //lcov added here to the array
      //...
    },
  },  
})
```

2. After adding `lcov`, run the following command in the root directory:

```bash
npm run coverage
```

<p align="center">
  <img width="40%" src="images/Admin_Lcov_And_Json_reported.png">
</p>

- Running this command should produce two report files under `./coverage`: 
  - `coverage-final.json`
  - `lcov.info`

3. Next, we need to configure the ``.gitlab-ci.yml` to pass the `lcov.info` report to the SAST stage.

```yaml
stages:
  - secrets-scan
  - dependency-scan
  - test-coverage
  - sast-scan

gitleaks_scan:
  rules:
    - when: never ##### DISABLED #####

dependency_scan:
  rules:
    - when: never ##### DISABLED #####

## THIS MUST BE ACTIVATED SINCE IT IS NEEDED BY THE NEXT STAGE
test-coverage:
  script:
    # - npm run coverage:json 
    - npm run coverage # The above command only produces a JSON report, so it was replaced
  artifacts:
    when: on_success
    expire_in: 1 week
    paths:
      - coverage/lcov.info  # Added This, which makes the report available for download and for next stages
      - coverage/coverage-final.json  

build-sonar:
  stage: sast-scan
  needs: ["test-coverage"]  # Added this, which automatically downloads the artifacts from the "needed" stage
  # ...
```

4. Edit the `sonar-project.properties` file and add the following line:
```ini
sonar.projectKey=<Your_Project_Key>
sonar.qualitygate.wait=true
sonar.javascript.lcov.reportPaths=./coverage/lcov.info # New Line Added
```

With these changes `SonarQube` should be able to access the generated coverage.

### `Quality Gate` 

Before you push the code changes, we need to discuss the `Quality Gate` concept. On the home page, click on the `Quality Gate` heading. 

<p align="center">
  <img width="80%" src="images/SQ_Quality_Gate.png">
</p>

The `Quality Gate` here defines conditions under which the test will succeed/fail.

| **Condition**                              | **Explanation**                                                                                                                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **New code has 0 issues**                  | The code should not introduce new **bugs**, **vulnerabilities**, or **code smells**. Existing (legacy) issues are tolerated, but **new code** must be clean.             |
| **All new security hotspots are reviewed** | Security hotspots are code sections that *might* be vulnerable depending on usage. Developers must **review and mark them** to ensure no unaddressed security risks. |
| **New code has sufficient test coverage**  | New code must be covered by **automated unit tests**. In this case, coverage must be **≥ 80%**. This reduces the risk of untested, buggy code being introduced.      |
| **New code has limited duplications**      | New code must avoid excessive **copy-paste**. Duplicated lines must be **≤ 3%** of new code. This ensures maintainability and reduces technical debt.                |

Any violation of the above conditions should cause the scan to fail, preventing insecure/low quality code from being delivered and used in production.

### `Quality Gate` Violation Test

As a test of the `Quality Gate` feature, we would like to violate one of the conditions to test whether the pipeline would fail or not. There are two ways we could do this.

**1. Moving the "New Code Baseline" Behind**

Since we already have "code problems" in the project, we could push the "new code baseline" behind. What this does is it will force `SonarQube` to treat the "old code" as new code. Since the "old" code is **now** considered "new", it will cause the pipeline to fail. Here are some of the definitions of "New Code" in `SonarQube`:

| **Baseline Option**    | **Description**                                               | **Use Case**                                   |
| ---------------------- | ------------------------------------------------------------- | ---------------------------------------------- |
| **Reference Branch**   | New code = changes compared to another branch (e.g., `main`). | Feature/develop branches vs. main.             |
| **Specific Time/Date** | New code = anything added/changed after a set date.           | Reset baseline after refactor or policy shift. |
| **Previous Analysis**  | New code = changes since the last SonarQube scan.             | Iterative cleanup between scans.               |
| **Previous Version**   | New code = changes since the last marked project version.     | Release-driven projects.                       |

This also explains why the issues did not cause the `Quality Gate` to fail initially. It is because the baseline is set to the current main branch, and the all of the faulty code was introduced in an old version of this branch. So, this problematic code is no longer considered "New Code".

**2. Introduce a New Software Problem**

Another easy way to violate the `Quality Gate` is by introducing a security problem intentionally in the next commit. We do this by looking at one of the reported problems and re-introducing it in a new place.


### Introducing a Code Problem

One of the reported problems is the following:

<p align="center">
  <img width="60%" src="images/SQ_Problem.png">
</p>

Here, `SonarQube` is asking us to avoid the usage of boolean literal in the condition. We can artificially recreate this problem by navigating to the same code site and adding a similar problem. An example could look like this:

```Typescript
// ./app/api/actions:
export async function PostMessageAction(formData: FormData) {
  //...

  // This is the original check
  if(hasPermission(usr.roles, "post.create")==false) {
      return {error: "Missing Permissions"};
  }

  // Here, we are literally just duplicating the check.
  if(hasPermission(usr.roles, "post.create")==false) {
      return {error: "Missing Permissions"};
  }

  //...
}
```

In the above code snippet, we do the check twice. This change has the following consequences:

1. The code coverage will be reduced, because the second check is never entered.

<p align="center">
  <img width="40%" src="images/Admin_Coverage_Reduction.png">
</p>

2. The logic of our code will not change (No bug is introduced). That is, if the first check is skipped, the second check will also be skipped because they have the same condition. If the first check is entered, the function will return and the duplicate code will not be touched.

3. This, however, should be flagged by `SonarQube` as a potential **"Maintainability"** issue. So, the `Quality Gate` must fail because of this.

### Running The Pipeline

Before running the pipeline, ensure that you have reviewed the steps and made the required configurations. After doing, this push the code changes to the repo.

<p align="center">
  <img width="80%" src="images/GLab_SAST_Quality_Gate_Failure.png">
</p>

As expected, the pipeline has failed due to `Quality Gate` Baselines were not met. To view the security scan report, press on the link in the logs.

<p align="center">
  <img width="80%" src="images/SQ_Failure.png">
</p>

There were two violations of the `Quality Gate`:
- The number of issues is more than 0, and `SonarQube` states `required = 0`.
- The coverage of the new code is less than 80%. Since 3 lines were added to the code and not all of these lines were covered by unit tests, the `Quality Gate` failed.

This shows that our SAST stage is functioning correctly, and it can detect static code problems before getting them pushed to production.

### Clean Up

Before you continue to the next stage, ensure that you can push changes to the pipeline without getting stopped by the SAST stage. You can do this by removing the code issue that was just added.

<p align="center">
  <img width="80%" src="images/GLab_SAST_Cleanup_Success.png">
</p>


<p align="center">
  <img width="80%" src="images/SQ_SAST_CleanUp.png">
</p>

---

# Build & Release, DAST, Deploy  

The remaining stages are possibly the most complex to implement as they require a lot of configurations that must be strictly correct. For the deployment, we will use a Blue/Green Deployment strategy. There are many benefits to this strategy, including:
- Easy recovery to a previous version of the app, if a problem is discovered. 
- There are is zero downtime when updating to a new version, because we will have at least one version ready at all times.

Here is how we are going to approach the next few stages.

**Build & Release:**

1. After completing all the tests, we build the `Next.js` app on `GitLab` push the required code files directly to the `APP VM` using `rsync`.

2. The pushed code files are stored under `/srv/chatapp/release/{timestamp}`. Thus, each code push will result in a new released version under the `/release` folder.

3. On th `APP VM`, we use symbolic linking to link `/srv/chatapp/test/current` to `/srv/chatapp/release/{timestamp}`.

4. With the code files ready and positioned correctly, we run a system service using `systemctl` that starts up a test `Next.js` server for testing. This testing instance should be accessible through http://192.168.20.2:3005 internally.

5. Finally, we seed the **test database** using the seeding endpoint. If the database is already seeded, then seeding has no negative effect and it will pass.

**DAST:**

1. In this stage, we issue an access token for the **DAST** test. Without an access token, the DAST agent cannot access any of the functionality or endpoints. We use `Playwright` to interact with the app, which results in creating a valid access token. 

2. Then, we initialize an [`OWASP ZAP`](https://www.zaproxy.org/docs/docker/about/) image and run a baseline scan against the system. We also include the access token as a part of the scan.

3. If the **DAST** scan completes without problems, we move to the **Deploy** stage.

<a id="deploy-table"></a>

**Deploy:**

In the deploy stage, we need to carefully act to ensure that we do not disrupt the system.

1. The running state of the system will be either of the following:

| Current State                  | Next Deployment Target | Rule                                           |
| ------------------------------ | ---------------------- | ---------------------------------------------- |
| Neither Blue nor Green running | Either Blue or Green   | Arbitrary choice, no active service            |
| Blue running                   | Green                  | Deploy to opposite color                       |
| Green running                  | Blue                   | Deploy to opposite color                       |
| Both Blue and Green running    | Older of the two       | Older service assumed to be the active version |

- When both are active, the older one is treated as the current running version. This assumes the older service has been live longer and represents the deployed version. Limitation: this can be wrong if the older version was reverted, restarted, or left running unintentionally. Other strategies include verifying via deploy timestamps, image SHAs, version tags/annotations, health checks, or current used ports.

- Let us say green is the selected color.

2. On the `APP VM`, we use symbolic linking again to link `/srv/chatapp/green/current` to `/srv/chatapp/release/{timestamp}`.

3. We then pass any required environment variables and run the green service. The environment variables are stored under `/etc/chatapp/{.env,blue.env,green.env,test.env}` beforehand.

4. After the service starts up, we reconfigure `Nginx` to point to the correct deployment spot.

---
A couple of notes before we proceed:
- For the testing stage, we will use the same `Keycloak` and `MySQL` instances. This is because of the limited system resources. However, we will isolate testing items from production.
  - For `Keycloak`, this can be done by creating an entirely new client dedicated for testing.
  - For `MySQL`, we create an entirely different database `(IAM_CHAT_APP_TEST)` and create a new user `(iam_test_user)`, who is only allowed to access this database.

- You will need to correctly set your environment variables under `/etc/chatapp/*`. In this folder, there will be 4 different environment variables files.

- You need to set up SSH keys for the `APP VM` and `DMZ VM`, since we need remote access from `GitLab` to them.
  - For the `APP VM`:
    - We need to move the code files from `GitLab` to `APP VM`
    - We also need to execute management scripts to start/stop services
  - For the `DMZ VM`:
    - We need to reconfigure `Nginx` to point to the correct destination

- Performing `systemctl` commands **remotely** requires passwordless `sudo` privilege on `APP VM` & `DMZ VM`.

## `APP VM` System Setup

First, we need to create a few directories in the `APP VM`, which will store configurations and code files.
```bash
# Create the folder structure and the 5 files
/etc/chatapp/
          - .env
          - blue.env
          - green.env
          - test.env #
          - cert.pem # Nginx server certificate
# Those files will contain different environment variables depending on which service is running.
# The ".env" file contains general environment variables that will be used by all builds,
# while "blue.env", "green.env", and "test.env" will contain variables used by each specific build
# For instance, one variable that will be used across all builds is the TLS certificate location
# NODE_EXTRA_CA_CERTS=/etc/chatapp/cert.pem
# We can safely place this variable inside the .env file which will be used by all chatapp@.service instances 

# Four folder paths
/srv/chatapp/blue/current
/srv/chatapp/green/current
/srv/chatapp/test/current
/srv/chatapp/release/
# The blue, green, and test folders has a "current" folder. We will use symbolic linking to point these folders to a version of the app.
# For example, while testing the app we can map:
# /srv/chatapp/test/current -> /srv/chatapp/release/2025-10-01T14-50-28
```

**Note: ensure that all of these folders are owned by the same SSH user. This will ensure that we do not run into permission problems later.**

In addition to the folders, we need a service file at `/etc/systemd/system/chatapp@.service`. The name of the service file is `chat@.service`. The `@` in the name allows us to run the service with different **names** as arguments. For instance, we will need to run three versions of the same service as follows:

| Instance unit name      | `%i` inside the unit | Example `EnvironmentFile` | Example `WorkingDirectory` |
| ----------------------- | -------------------- | ------------------------- | -------------------------- |
| `chatapp@test.service`  | `test`               | `/etc/chatapp/test.env`   | `/srv/chatapp/chatapp/test`    |
| `chatapp@green.service` | `green`              | `/etc/chatapp/green.env`  | `/srv/chatapp/chatapp/green`   |
| `chatapp@blue.service`  | `blue`               | `/etc/chatapp/blue.env`   | `/srv/chatapp/chatapp/blue`    |


```ini
# You can use this command to create the service file
sudo tee /etc/systemd/system/chatapp@.service >/dev/null <<'UNIT'
# /etc/systemd/system/chatapp@.service
[Unit]
Description=Chatapp (%i)
After=network.target

[Service]
Type=simple
# Change USER & GROUP
User=app
Group=app

# Common + per-instance env files
EnvironmentFile=-/etc/chatapp/.env
EnvironmentFile=-/etc/chatapp/%i.env

# Each color has its own tree and 'current' symlink
WorkingDirectory=/srv/chatapp/%i/current

ExecStartPre=/usr/bin/test -x /home/app/.nvm/versions/node/v22.18.0/bin/node
ExecStartPre=/usr/bin/test -d /srv/chatapp/%i/current

# Non-standalone Next.js: start the built app from .next using the Next CLI
# Adjust node path if needed (e.g., /usr/bin/node)
ExecStart=/home/app/.nvm/versions/node/v22.18.0/bin/node ./node_modules/next/dist/bin/next start -p ${PORT}

Restart=always
RestartSec=3

# Basic hardening (optional, safe defaults)
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT
```
File: [chatapp@.service](files/chatapp@.service)

In the above file, ensure that you change the USER & GROUP and the path to `node`. 

## SSH Keys Setup

You need to generate an SSH key for the `CI/CD VM`, which you will use to connect to both target VMs. Then, on those machines, you need to configure users that you can connect to using ssh keys.

On the `CI/CD VM`, generate a public/private key pair for SSH.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "key for app and dmz"
```

Then you can copy the private key to the other ssh servers.

### DMZ Virtual Machine

On the `CI/CD VM`, the `ssh-copy-id` command can help you copy and configure the key. Here, we copy the public key to the `DMZ VM`.

```bash
cid@cid:~$ ssh-copy-id -i ~/.ssh/id_ed25519.pub dmz@192.168.10.2
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/cid/.ssh/id_ed25519.pub"
The authenticity of host '192.168.10.2 (192.168.10.2)' can't be established.
ED25519 key fingerprint is SHA256:Z0yNaDBYibUvvhh3h7tzFOoMrZ8MV7M8x64UkxY9OBM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
dmz@192.168.10.2's password:

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'dmz@192.168.10.2'"
and check to make sure that only the key(s) you wanted were added.
```

### APP Virtual Machine

Here, we copy the public key to the `APP VM`.

```bash
cid@cid:~$ ssh-copy-id -i ~/.ssh/id_ed25519.pub app@192.168.20.2
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/cid/.ssh/id_ed25519.pub"
The authenticity of host '192.168.20.2 (192.168.20.2)' can't be established.
ED25519 key fingerprint is SHA256:omBYffZlIL8OBzaDlQWvCANfak/dpYpwvTU+wJ/nmqg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
app@192.168.20.2's password:

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'app@192.168.20.2'"
and check to make sure that only the key(s) you wanted were added.
```

### GitLab SSH

The SSH servers now can now recognize those public keys without issues. However, on `GitLab`, since a container does not have access to the host's filesystem, we will have to pass the private key to the container using environment variables using CI/CD variables.  

<p align="center">
  <img src="images/GLab_SSH_KEY.png">
</p>

## `MySQL` Database Setup for Testing

On the `APP VM`, ensure that you have created a separate database and user for testing. Example commands:

```bash
CREATE DATABASE IAM_CHAT_APP_TEST CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'iam_test_user'@'localhost' IDENTIFIED BY 'YourStrongPassword';
GRANT ALL PRIVILEGES ON IAM_CHAT_APP_TEST.* TO 'iam_test_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

For the **test environment variables** on the `App VM`, you should also set the values as follows under the `test.env`:

```ini
#/etc/chatapp/test.env
# Other variables ... 
DATABASE_NAME=IAM_CHAT_APP_TEST
DATABASE_URL="mysql://iam_test_user:YourStrongPassword@localhost:3306/IAM_CHAT_APP_TEST"
# ...
```

## `Keycloak` Client Configuration for Testing

In addition to the database, we should create another `Keycloak` client for testing.

<p align="center">
  <img src="images/KC_New_Client.png">
</p>

We will come back to `Keycloak` client later, as we need to do things differently for DAST to work.

## Passwordless Sudo

Since we will be executing remote `systemctl` commands from `GitLab` **automatically**, some `systemctl` commands need to be allowed without having to pass the user's password. 

This can be configured with the `visudo` command on the `APP VM`, and adding a line similar to the following:

```bash
## Visudo Command ...

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# THIS IS THE ONLY LINE THAT IS ADDED
# Change the name of the user "app" to your account on the App VM
app ALL=(ALL) NOPASSWD: /bin/systemctl start chatapp@test.service, /bin/systemctl stop chatapp@test.service, /bin/systemctl restart chatapp@test.service

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
```

**Note: The placement of this line is important. It must be placed towards the end of the file, because this file uses a last matching strategy. So, if you put this line early in the document, it may not work.**


## Other Configurations

In addition to that, you need to ensure the values of the environment variables. Specifically, the URLs need to be correct or otherwise you will run into many problems. I have made a separate [file](errors.md) that shows some of the problems I ran into while configuring the pipeline. 

## Pre CI/CD Configuration

Before continuing, it is a good idea to test whether you are able to run the chat-app from their place using services.

```bash
# Example:
# Setup a Symbolic link
ln -sfn /srv/chatapp/release/2025-10-03T05-54-26 /srv/chatapp/test
# Run The service
sudo systemctl start chatapp@test.service
```

---

# Building The Remaining Stages Pipeline

In the following stages, we will create a new `.gitlab-ci.yml` file for the last three stages. After we finish, we will merge both files together.

## Build Stage

For the build stage, here is the config file.

```yml
stages: ["build & release"]

variables:

  # Depends on the APP VM
  RSYNC_USER: "app"
  RSYNC_HOST: "192.168.20.2"
  APP_BASE: "/srv/chatapp"
  RSYNC_BASE: "/srv/chatapp/release"
  
  GIT_STRATEGY: clone

  # DO NOT FORGET to pass these variables in the CI/CD Settings, NOT HERE
  # SEEDING_SECRET: $SEEDING_SECRET
  # SSH_PRIVATE_KEY: $SSH_PRIVATE_KEY

  # The base address of the testing server
  TESTING_BASE_URL: "192.168.20.2:3005"

"build & release":
  stage: "build & release"
  image: node:22-alpine

  ## Cache some of the build artifacts to avoid long builds
  cache:
    key:
      files:
        - package-lock.json
    paths:
      - .npm
      - .next/cache
    policy: pull-push
  before_script:
    - npm config set cache $CI_PROJECT_DIR/.npm --global
    # Install deps
    - apk add --no-cache openssh-client rsync python3
    # Add the private key to The SSH Client
    - mkdir -p ~/.ssh
    - echo "$SSH_PRIVATE_KEY" | tr -d '\r' > ~/.ssh/id_rsa
    - chmod 600 ~/.ssh/id_rsa
    # Recognize the app VM as a known host
    - ssh-keyscan -H "$RSYNC_HOST" >> ~/.ssh/known_hosts
    # Generate a timestamp to be used for the folder name
    - export TS="$(date +'%Y-%m-%dT%H-%M-%S')"
    - echo "TIMESTAMP=$TS" >> variables.env
  script:
    ## Build 
    - npm ci --omit=dev
    - npm run build
    # load the timestamp as an env variable
    - source variables.env
    # Create a folder and sync the files
    - ssh ${RSYNC_USER}@${RSYNC_HOST} "mkdir -p ${RSYNC_BASE}/${TIMESTAMP}"
    - rsync -a --info=stats2 --exclude='repo_resources' --exclude='test' --exclude='.gitignore' --exclude='.gitlab-ci.yml' --exclude='README.md' --exclude='docker-compose.yml' --exclude='seeder.py' --exclude='sonar-project.properties' --exclude='vitest.config.mts' ./ ${RSYNC_USER}@${RSYNC_HOST}:${RSYNC_BASE}/${TIMESTAMP}/
    # Create a symlink and restart the test service
    - ssh ${RSYNC_USER}@${RSYNC_HOST} "sudo systemctl stop chatapp@test.service || true"
    - ssh ${RSYNC_USER}@${RSYNC_HOST} "ln -sfn ${RSYNC_BASE}/${TIMESTAMP} ${APP_BASE}/test/current"
    - ssh ${RSYNC_USER}@${RSYNC_HOST} "sudo systemctl start chatapp@test.service"
    # Seeding
    # Give 10 seconds for the server to startup and then seed it
    - sleep 10
    - python3 seeder_sec.py "http://${TESTING_BASE_URL}"

  artifacts:
    reports:
      dotenv: variables.env
```

The build stage is as we described before:
1. Download dependencies
2. Configure SSH client
3. Generate a timestamp and put it in `variables.env`
4. Build the app
5. Create a folder using the timestamp as the name
6. Use `rsync` to deliver the required files, excluding unnecessary files 
7. Create a symlink and restart the test service
8. Wait for a few seconds and seed the database of the app

The `seeder_sec.py` is a variation of the script we have worked on before. This one disallows using HTTPs without providing a trusted certificate. The code is available [seeder_sec.py](files\seeder_sec.py). For this stage however, we do not need to use the TLS feature, as the test sever is hosted at http://192.168.20.2:3005.

For this pipeline to work, however, you need to define the following variables:

| Variable         | Purpose              |
|------------------|----------------------|
| `SEEDING_SECRET`   |  Used to seed database|
| `SSH_PRIVATE_KEY ` | Used for SSH         |

<p align="center">
  <img width="80%" src="images/GLab_Build_Variables.png">
</p>

### Running The Pipeline

Now push the configuration changes to run the pipeline

**Output Log:**

First, the pipeline should complete successfully without problems.

<p align="center">
  <img width="80%" src="images/Glab_Success_Build_Release.png">
</p>

**Built Version:**

Second, you should be able to see a new version of the app under `/srv/chatapp/release`.

<p align="center">
  <img width="80%" src="images/APP_New_Release.png">
</p>

**Running Test Version:**

Finally, a test version of the app should be accessible via http://192.168.20.2:3005

<p align="center">
  <img width="80%" src="images/Chat_Test_Running.png">
</p>

You can even interact normally with this version as a user, but this is only accessible internally. Thus, you need to establish an SSH tunnel and use it. Nevertheless, this is only a test version and is only intended to be a target for the next DAST scan.


## DAST Stage

In the Dynamic Application Security Testing (DAST) stage, we will utilize `OWASP ZAP` to scan the deployed test version. However, the first problem that we need to address is the fact that the app requires an access token to function correctly. On its own, `OWASP ZAP` can not reliably do authentication with `Keycloak` and acquire an access token. Thus, we need to provide this access token to `OWASP ZAP` before it starts the scan.

### Acquiring a Token Manually

To acquire a valid access token, we can simply login using the account that we would like to use for the test, do a full login, and extract the cookies from the browser.

<p align="center">
  <img width="80%" src="images/CA_Cookies_Manual.png">
</p>

The most important cookie for maintaining the session is the `__Secure-authjs.session-token` cookie. This cookie contains the encrypted JWT generated by the application. By providing this cookie to the scanner, it can bypass the authentication requirement and start testing the actual functionality.

This method, however, is fragile and requires manually setting the token. On top of that, the token may at some point expire, which could possibly render the automated scan useless.

### A Better Approach

The better approach automatically generates an access token by walking the application's real login flow with a browser automation tool such as `Playwright` (`Playwright` is a browser automation tool, i.e, controls a real browser using code): it performs the UI login including CSRF handling and any testable MFA hooks, captures the httpOnly session cookie or JWT from the browser context, and supplies that token to ZAP either by injecting the cookie or by proxying the login through ZAP so the scanner records an authenticated session, producing fresh, repeatable scans without manual cookie copying.

For this reason, the DAST stage will be broken down into to sub-steps. The first is about acquiring the access token, and the second is about performing the DAST scan.

### Access Token Acquisition Stage

#### Minimum Setup

Before we start, ensure that the **test chat-app** instance is running. Otherwise, you can not generate the token. If the last stage ran successfully, then you should be in a position to continue directly.

<p align="center">
  <img width="80%" src="images/APP_Test_Running.png">
</p>

Also, ensure that you can access the website and perform full log-in without problems via the DMZ SSH tunnel.

<p align="center">
  <img width="80%" src="images/CA_LoggedIn.png">
</p>

Finally, you should create an IAM user dedicated for the DAST scan.

<p align="center">
  <img width="80%" src="images/KC_DAST_User.png">
</p>

This user should have full access rights to the app, which can be granted by assigning the user a `chat-admin` role (either realm role or client realm will work).

<p align="center">
  <img width="80%" src="images/KC_DAST_ROle.png">
</p>

#### `.gitlab-ci.yml` Configuration

Here are the configurations needed for this stage:

```yml
stages: [auth]

variables:
  # KEYCLOAK_USER: $KEYCLOAK_USER -> Define in the CI/CD settings
  # KEYCLOAK_PASS: $KEYCLOAK_PASS -> Define in the CI/CD settings

  # These are required for connectivity with Keycloak, if you choose different values make sure you change them
  PRODUCTION_BASE_URL: "local.keycloak.com" 
  HOSTS_ENTRY: "192.168.10.2 ${PRODUCTION_BASE_URL}"

  # These variables are used by extract_cookie.py script.
  # If your test server is located in the same IP as here, do not make changes to these values and keep them uncommented
  # APP_HOST: "192.168.20.2" -> default value if not set
  # START_URL: "http://192.168.20.2:3005/api/auth/signin" -> default value if not set

auth-cookies:
  stage: auth
  image: mcr.microsoft.com/playwright/python:v1.55.0-jammy
  script:
    # Add hosts entry into the container (the container cannot resolve the address otherwise)
    - echo "$HOSTS_ENTRY" >> /etc/hosts    ## point the cache to the current directory
    - python -V
    - python -m pip install --upgrade pip
    - pip install --no-cache-dir "playwright==1.55.0"
    - python extract_cookie.py
  artifacts:
    expire_in: 1h
    paths:
      - cookies.json
      - cookies_header.txt
```
File: [6-AUTH-stage.gitlab-ci.yml]( files/6-AUTH-stage.gitlab-ci.yml)

Notice that you need to add the username/password in the CI/CD settings.

<p align="center">
  <img width="80%" src="images/GLab_DASt_CRED.png">
</p>

In addition, you will need to include a new script file: [extract_cookie.py](./files/extract_cookie.py), which should be placed in the root of the project. This code file uses `Playwright` to interact with test app, perform a full login using the provided credentials, and produce two files containing the cookies: `cookies.json` and `cookies_header.txt`. These files are marked as artifacts, so that we can access them in the next stage.

#### Testing The Pipeline

Running the pipeline now should succeed showing that it managed to write the cookies.

<p align="center">
  <img width="80%" src="images/GLab_Auth_Stage.png">
</p>

In addition, you should be able to see these cookie files as downloadable artifacts on the right. Both of them have the same values, but structured differently.

<p align="center">
  <img width="80%" src="images/Admin_Cookie_JSON_EX.png">
</p>


To test the validity of the token, navigate to your browser (tunneled via ssh to the DMZ) and visit http://192.168.20.2:3005. You should be taken to the sign in page of the app. Here, you do not do a normal sign. Rather, open `inspect -> Storage -> Cookies`

<p align="center">
  <img width="80%" src="images/App_DevMode.png">
</p>

Under the `cookies`, menu add a new cookie whose key is `authjs.session-token` and its value is found in the file you just downloaded from `GitLab` artifacts. Be sure to copy the entire value of the cookie.

<p align="center">
  <img width="80%" src="images/App_Cookies_Placed.png">
</p>

Now that you have added the cookie, navigating to http://192.168.20.2:3005 should show the app's chat screen, meaning the token that was generated by the pipeline is valid.

<p align="center">
  <img width="80%" src="images/App_Cookie_Coppied_Working.png">
</p>

Now that the token is getting generated, we can move on to the next stage.

### DAST OWASP ZAP Baseline Scan

In this stage, we use [`OWASP ZAP` baseline scan](https://www.zaproxy.org/docs/docker/baseline-scan/). The baseline is a passive scan that does not perform any attack against the app and runs for a short time. While it is not a comprehensive scan, it suffices for demonstration. `Owasp ZAP` provides much more [intensive scans](https://www.zaproxy.org/docs/docker/) that are much more powerful. However, they require much more setup and are much more resource intensive.

```yml
stages: [auth, DAST]

variables:
  # KEYCLOAK_USER: $KEYCLOAK_USER
  # KEYCLOAK_PASS: $KEYCLOAK_PASS
  PRODUCTION_BASE_URL: "local.keycloak.com"
  HOSTS_ENTRY: "192.168.10.2 ${PRODUCTION_BASE_URL}"

auth-cookies:
  stage: auth
  image: mcr.microsoft.com/playwright/python:v1.55.0-jammy
  script:
    # Add hosts entry into the container (the container cannot resolve the address otherwise)
    - echo "$HOSTS_ENTRY" >> /etc/hosts    ## point the cache to the current directory
    - python -V
    - python -m pip install --upgrade pip
    - pip install --no-cache-dir "playwright==1.55.0"
    - python extract_cookie.py
  artifacts:
    expire_in: 1h
    paths:
      - cookies.json
      - cookies_header.txt

zap_baseline:
  stage: DAST
  needs: ["auth-cookies"]  # Allows acquiring the cookie files from the auth stage
  image: zaproxy/zap-stable
  variables:
    ZAP_TARGET: "http://192.168.20.2:3005"
  script:
    - export ORG_WORK_DIR="$(pwd)"
    # Create and move to the correct working directory
    - mkdir -p /zap/wrk
    # Use the cookie header from the file
    - export ZAP_AUTH_HEADER=Cookie
    - export ZAP_AUTH_HEADER_VALUE="$(tr -d '\n\r' < cookies_header.txt)"
    # Optional: limit header to a site name match
    # - export ZAP_AUTH_HEADER_SITE="192.168.20.2"
    - zap-baseline.py -t "$ZAP_TARGET" -I -r "zap-baseline-report.html" -J "zap-baseline-report.json" -w "zap-baseline-report.md"
    - cp -r /zap/wrk/* "$ORG_WORK_DIR"/
    # Stop the test service - Add the required environment variables
    # - ssh ${RSYNC_USER}@${RSYNC_HOST} "sudo systemctl start chatapp@test.service"
  artifacts:
    when: always
    paths:
      - zap-baseline-report.html
      - zap-baseline-report.json
      - zap-baseline-report.md
```
File: [6.1-AUTH-DAST-stage.gitlab-ci.yml](./files/6.1-AUTH-DAST-stage.gitlab-ci.yml)

Here, we use a [`docker` image](https://www.zaproxy.org/docs/docker/baseline-scan/) provided by OWASP that has a scanning script. This script runs against the test web app and generates a report 3 different formats, which we declare as artifacts.

Running the pipeline now should perform the DAST test and report the results.

<p align="center">
  <img width="80%" src="images/GLab_AUTH_DAST_Success.png">
</p>

Downloading the artifacts, you can find an HTML containing the detections of the scan.

<p align="center">
  <img width="80%" src="images/OWASP_Report.png">
</p>

HTML FILE (Correct The Extension To View The Report): [zap-baseline-report.html.txt](result/zap-baseline-report.html.txt)

We will not be going through the report, as this out of the scope of the project. Also, note that many of the reported problems can simply be fixed by updating the libraries to the latest versions, and some are just false-positives.

## Deployment Phase

In the deployment phase, we simply need to find which spot is currently running (green/blue), run the service in the most appropriate spot, and point `Nginx` to the new version. We keep both versions running, for the simple reason of being able to quickly revert without problems.

### Setup

First, we will create a `Python` script at `/srv/chatapp/scripts/deploy.py`. The input for this script is the current timestamp chosen of the current build. The script determines which color to deploy one and returns it as either `green` or `blue`. It selects the color based on the [table](#deploy-table) shown earlier.

**The Script deploy.py script**

On your `APP VM`, place the `deploy.py` under `/srv/chatapp/scripts/`.

<p align="center">
  <img src="images/APP_Deploy_Script.png">
</p>

**Passwordless Sudo**

The `deploy.py` script executes various `sudo systemctl` commands, and we need to allow them without getting prompted for a password. On the `APP VM`, using the `visudo` command, replace the line that we added in the build stage with the following lines one:

```bash
# OLD LINE Added in the build stage
# app ALL=(ALL) NOPASSWD: /bin/systemctl start chatapp@test.service, /bin/systemctl stop chatapp@test.service, /bin/systemctl restart chatapp@test.service

# New Lines - Change "app" to your username
app ALL=(root) NOPASSWD: /bin/systemctl start chatapp@*.service, \
 /bin/systemctl stop chatapp@*.service, \
 /bin/systemctl enable chatapp@*.service, \
 /bin/systemctl is-active chatapp@*.service, \
 /bin/systemctl show chatapp@*.service, \
 /bin/systemctl status chatapp@*.service, \
 /bin/systemctl disable chatapp@*.service
```

|Stage|Commands Needed to Be Passwordless|
|----|------|
|build| `systemctl stop`, `systemctl start`|
|deploy| `systemctl is-active`, `systemctl is-active`, `systemctl enable`, `systemctl start`, `systemctl start`|

These commands will be done automatically to manage the deployment and they need to be passwordless. If they were not passwordless, the pipeline will fail since we will not be feeding the password manually.

**Blue & Green Environment Variables**

Under `/etc/chatapp/`, create two new environment variable files with `PORT` added as follows:
```ini
# /etc/chatapp/blue.env
PORT=3001
```

```ini
# /etc/chatapp/green.env
PORT=3002
```

When `systemctl` starts a `chatapp` service, it loads the `/etc/chatapp/.env` files first for all cases. In addition to the general environment file, it also loads `/etc/chatapp/{color}.env`, where the color is the value you pass after the `@`. 

```bash
sudo systemctl chatapp@green.service
# After the @ is "green"
# So it loads /etc/chatapp/green.env too
```

**Check For An Existing Version**

Before you automate the process, it is a good idea to test things manually to see if there are any problems. Find a version that is already build it your system under the release folder and execute the deploy script using this version.

<p align="center">
  <img width="70%" src="images/APP_Blue_Run.png">
</p>

Now this version is accessible internally using http://192.168.20.2:3001. 

<p align="center">
  <img src="images/CA_Internal.png">
</p>

However, this version is meant to be accessible externally, so we will have to configure `Nginx` later.

### Remote Test

Now on your `CI/CD VM`, you should be able to execute the script remotely without problems. The following sequence shows how the `deploy.py` script behaves:

```bash
# Initially, neither blue nor green is running

# Executing the command without a valid timestamp is no applicable
cid@cid:~$ ssh app@192.168.20.2 "python3 /srv/chatapp/scripts/deploy.py"
usage: deploy.py <timestamp>

# First execution with a valid timestamp -> blue is selected
cid@cid:~$ ssh app@192.168.20.2 "python3 /srv/chatapp/scripts/deploy.py 2025-10-03T05-54-26"
blue

# Second execution with a valid timestamp -> green is selected
cid@cid:~$ ssh app@192.168.20.2 "python3 /srv/chatapp/scripts/deploy.py 2025-10-03T05-54-26"
green
## Now, both colors are running
## However, on the APP VM, stop the green color. This is to test if it will correctly take the inactive spot

# Since green was deactivate, it is the available spot and is chosen
cid@cid:~$ ssh app@192.168.20.2 "python3 /srv/chatapp/scripts/deploy.py 2025-10-03T05-54-26"
green

## Here, do not stop any of the services, both blue and green are running
## Since blue was active first, it should be the one chosen
cid@cid:~$ ssh app@192.168.20.2 "python3 /srv/chatapp/scripts/deploy.py 2025-10-03T05-54-26"
blue
## Because green started after blue, green is regarded as the new version and it is the currently running instance. If we choose green here, the service maybe lost for a few seconds until the service starts up.

```

<p align="center">
  <img width="60%" src="images/CID_Color_Selection.png">
</p>

### DMZ VM Configuration

In order to be able to remotely reconfigure `Nginx` to point to a different port, we need to make a template file, where we can replace the value of the application port as we wish. 

First, make a copy of the `Nginx` configuration folder that you have and place it at `/etc/nginx/templates/app.conf.template` as `app.conf.template`.

```bash
sudo cp /etc/nginx/sites-available/default /etc/nginx/templates/app.conf.template
```

In the new file, we change only one line:

```nginx
server {
    # ...
    ## The Entire File Stays the same
    location / {
        # Before
        # proxy_pass http://192.168.20.2:3000;
        # The only line that changes
        proxy_pass http://192.168.20.2:${APP_PORT};
    } 
  # ...
}
```
Full File: [app.conf.template](./files/app.conf.template).

Next, we create a new script file in the same directory `/etc/nginx/templates`.

```bash
sudo touch /etc/nginx/templates/reload-nginx.sh
sudo chmod 744 /etc/nginx/templates/reload-nginx.sh
```

The content:

```bash
#!/bin/bash
# Usage: reload-nginx.sh <APP_PORT>

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <APP_PORT>"
  exit 1
fi

APP_PORT="$1"
export APP_PORT

envsubst "\${APP_PORT}" < /etc/nginx/templates/app.conf.template \
  | tee /etc/nginx/sites-available/default >/dev/null

nginx -t
systemctl reload nginx
```
Full Script: [reload-nginx.sh](./files/reload-nginx.sh)

This script accepts a port as an argument, takes the `Nginx` template file `app.conf.template`, replaces all matches of the `${APP_PORT}` with the port that we provided, places the `Nginx` configuration at `/etc/nginx/sites-available/default`, and reloads `Nginx`. 

Locally, the script can be executed as follows:
```bash
# This would reconfigure `Nginx` to point to 3001, in a blue build for instance,
sudo /etc/nginx/templates/reload-nginx.sh 3001
```

Finally, since this script executes privileged commands **remotely**, we need call it with passwordless `sudo`. We configure this using `visudo` on the `DMZ VM`.

```bash
# Add this to the end of the file that Visudo
dmz ALL=(ALL) NOPASSWD: /etc/nginx/templates/reload-nginx.sh *
```

We will use this script to remotely change the port `Nginx` is pointing to for the chat-app. To test this, open a terminal in your `CI/CD VM`, and execute the following command:

```bash
ssh dmz@192.168.10.2 "sudo /etc/nginx/templates/reload-nginx.sh 3005"
```

Running this should succeed without asking for a password. If your test chat-app server is still running, you should be able to access it externally as if it was the original actual app via https://192.168.33.6.

### Configure `.gitlab-ci.yml`

```yml
deploy:
  stage: deploy
  image: alpine:3.22
  before_script:
    # Omitted
  script:
    # Load the timestamp as an env variable
    # - source timestamp.env
    - echo "Found TIMESTAMP=$TIMESTAMP"
    # Deploy in the APP VM and return the chosen color
    - color=$(ssh ${RSYNC_USER}@${RSYNC_HOST} "python3 ${APP_BASE}/scripts/deploy.py ${TIMESTAMP}")
    # Decide the port from the color
    - if [ "$color" = "blue" ]; then export APP_PORT=3001; else export APP_PORT=3002; fi
    # Print chosen color, and the internal address of the service
    - export INTERNAL_SERVICE_ADDRESS="http://${RSYNC_HOST}:${APP_PORT}"
    - > 
      echo "Deploying - ${color} ${TIMESTAMP}: at ${INTERNAL_SERVICE_ADDRESS}"

    # Reconfigure Nginx to point to the new deployed version
    - ssh ${DMZ_USER}@${DMZ_HOST} "sudo /etc/nginx/templates/reload-nginx.sh ${APP_PORT}"
    # Wait for 10 seconds and seed the production database
    - sleep 10

    # Seeding can either be done using HTTP or HTTPS
    - python3 seeder_sec.py "https://${PRODUCTION_BASE_ADDRESS}"
```

As you can see, the last stage relies on the **build & release**, which has the current timestamp. `GitLab` passes it automatically as per our configuration. In this stage, we remotely execute the `deploy.py` script which runs the app in the green/blue spot and returns the color used. The color is used to determine which port to use; `blue-> port=3001` and `green-> port=3002`. Then, we remotely execute the `reload.nginx.sh` script, which points the `Nginx` to the correct internal port. Finally, we seed the app's database.

---

# Running The Build & Release, DAST, and Deploy Stages

The pipeline config file `.gitlab-ci.yml` of the last three stages is found under [7-Build-Release-DAST-Deploy-.gitlab-ci.yml](./files/7-Build-Release-DAST-Deploy-.gitlab-ci.yml).

## Environment Variable Setting 

Ensure that you define all CI/CD variables in GitLab settings AND inside the script file itself. 

<p align="center">
  <img width="70%" src="images/GLab_All_Vars.png">
</p>

On `GitLab`, these are the environment variables defined. Ensure the options also match the ones shown. A noteworthy variable here is the `SEEDING_CA_CERT`. This variable stores the **PATH** to the public key certificate of the `Nginx` server. This is required to perform seeding via HTTPs (not required if you will seed with HTTP).

When defining this variable in `GitLab`, you paste the content of the public key certificate, but choose `File`.

<p align="center">
  <img  src="images/GLab_SEEDING_CA_CERT.png">
</p>

This variable does not store the **value** of the variable. Rather, it stores the **PATH** to a file, where the content is in.

Example:
```bash
$ echo $SEEDING_CA_CERT
/etc/chatapp/cert.pem
$ cat $SEEDING_CA_CERT
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIUL4NlWs7LUlG0EgydPk29ABw0showDQYJKoZIhvcNAQEL
```

## Running The Pipeline

Once everything is ready, you can push the new configurations and run the pipeline.

<p align="center">
  <img src="images/GLab_Last_Stages_Succeed.png">
</p>

As you can see, all the pipeline stages executed successfully. However, we need to verify that the pipeline has done its job correctly. We can do this by verifying the logs and the environment.

### Build Stage

<p align="center">
  <img  src="images/GLL_Build_Logs.png">
</p>

| Expectation | Proof | Explanation|
|-------------|------|---- |
| New Release Appear Under `/release` | <img width=500 src="images/GLL_Build_New_Release.png">| The latest release is the `2025-10-06T04-01-35`, which is a result of `GitLab`'s build. |
| `./test/current` Folder Symbolically Mapped To The new release |<img src="images/GLL_Build_Test_Sym_Link.png">| Before running the test server using `systemctl`, this directory must be mapped. If it is mapped correctly, then the test service should start without problems. |
| Test Server Ran And Seeding Succeeded | <img width=500 src="images/GLL_Build_Seeding.png">| Seeding log shows a success here, meaning the test server ran without problems. |

### DAST Stage

This stage is split into two sub-tasks.

**Cookie Acquisition Logs:**

<p align="center">
  <img src="images/GLL_DAST_AUTH_LOG.png">
</p>

**Scan Logs:**

<p align="center">
  <img src="images/GLL_DAST_SCAN_Logs.png">
</p>

These two stages do not make any lasting change to the environment, and so we move on to the last stage.

### Deploy Stage

<p align="center">
  <img src="images/GLL_Deploy_Logs.png">
</p>


| Expectation | Proof | Explanation|
|-------------|------|---- |
| Chosen Color Appear in The Logs | <img src="images/GLL_DEPLOY_COLOR.png">| The latest release `2025-10-06T04-01-35` was deployed on the green spot (port 3002). |
| `./green/current` Folder Symbolically Mapped To The new release |<img src="images/GLL_DEPLOY_GREEN_LINKED.png">| The symbolic link must point to the new release. |
| `chatapp@green.service` Is Running On Port 3002 |<img src="images/GLL_DEPLOY_GREEN_SYS.png">| This indicates that the service was deployed and started up correctly at the expected spot. |
| `Nginx` Configuration Points To Port 3002| <img  src="images/GLL_Deploy_Nginx_File.png"> | `Nginx` must correctly point towards the service on `App VM` |
| Seeding Succeeded | <img width=500 src="images/GLL_Deploy_Seeding.png">| Seeding log shows a success here. |
| Service Externally Accessible at https://192.168.33.6| <img width=500 src="images/GLL_Deploy_Externally_Accessible.png"> | If the service is now externally accessible, then we have correctly built the pipeline and any code change is automatically and securely deployed |

---

# End-To-End Secure CI/CD (DevSecOps)

Lastly, we merge all stages into a single `.gitlab-ci.yml` file so that we have a full pipeline, starting with **Security Scanning** and ending with **Deployment**.

Full Pipeline: [8.full-pipeline.gitlab-ci.yml](files/8.full-pipeline.gitlab-ci.yml)

<p align="center">
  <img src="images/GLF_Full_Pipeline.png">
</p>

With that, the pipeline is now ready for automatic code delivery. Now, with any code change that is pushed to the repository, all the stages are executed performing the various scans, security processes, build and deployment steps automatically. This ensures that every commit passes through code quality checks, security validations, automated testing, and build verification before being deployed to the target environment. The result is a consistent, secure, and reliable delivery process with minimal manual effort and faster feedback for developers.

---

# General Discussion
- The pipeline covered many of the major steps that a typical DevSecOps CI/CD pipeline has. However, actual pipelines may contain many more stages.
- Many of the stages of the pipeline can be invoked even before pushing the code to the pipeline. For instance, in addition to executing `GitLeaks` in the pipeline, we execute it on the developers computer. This way, secrets are prevented from getting into the repository in the first place.
- We have only briefly touch upon secret generation, such as that we did for generating a test. In real environments, many of the actions that we take require issuing short-lived secrets, and there are tools like `Vault` that does such a job. For instance, rather than having a full SSH access to a user on the target machine, `Vault` allows us to generate a temporary secret, say to an EC2 unit, where we can deploy the app there.
- In many places of the CI/CD pipeline, I tried to add Caching to speed up rebuilds. However, caching is not the only way to speed up `GitLab`. Since we only had a single runner, we could not run multiple tasks in parallel. In real environments, you may have a cluster of runners that allow us to execute multiple stage simultaneously.
- The Blue/Green deployment that we have done here can switch with almost zero downtime. Since reloading `Nginx` can take a few milliseconds, this is the only time where access to the service.
- The Blue/Green deployment also allow us to revert to the last deployment without much difficulty. For instance, if we discovered that there is a bug in the latest build, and the latest build was deployed in the blue spot, we can simply execute a remote SSH command to point to the other color.
  - This is possible, because we do not shutdown the older version of the service. We rather keep it on and just point `Nginx` to the new version.
```bash
# Remotely Switch to Green
cid@cid: ssh dmz@192.168.10.2 "sudo /etc/nginx/templates/reload-nginx.sh 3002"

# Or locally from the DMZ itself
dmz@dmz: sudo /etc/nginx/templates/reload-nginx.sh 3002
```
- We can also easily create a script to revert to the older version automatically. The script would check the timestamps for the blue/green builds and point `Nginx` to the older one.
- Deployment can be customized even more by integrating a `Container Image Repository`, and deploying service using
 `Docker` or `Kubernetes`.

---

# Summary

In this phase, we built an 8 stage DevSecOps pipeline, starting with Secrets Scanning & ending with a secure deployment.

We began with reconfiguring the `GitLab` Runner to use the `Docker` executor instead of the shell executor to isolate build tools and simplify configuration. We registered the runner with administrative privileges, assigned `node:lts` as the default image, and confirmed it **appeared online** in `GitLab`. After migrating the chat-app repository to `GitLab`, we incrementally built the CI/CD pipeline, validating each stage before proceeding.

We began with a `Gitleaks` secrets scan stage that analyzed the repository and failed the pipeline when secrets were found. After purging the commits containing exposed variables, we enforced a `full-clone` strategy to prevent cached leaks. We then added a dependency scan using `npm audit` that failed on `high` or `critical` vulnerabilities, followed by a `Vitest`-based test and coverage stage that generated JSON and LCOV reports for later stages.

Next, we integrated `SonarQube` via `Docker` Compose with `PostgreSQL`, connected it to `GitLab` through an API token, and configured `sonar-project.properties` to read `LCOV` coverage from previous runs. The SAST stage used the `SonarQube` scanner CLI to run static analysis, apply `Quality Gate` rules, and fail when thresholds such as coverage or issue count were not met.

We built and released the `Next.js` app using `node:alpine`, cached dependencies, and used SSH-based deployment using `rsync` to copy files to `/srv/chatapp/release/<timestamp>` on the `App VM`. Each deployment created a new directory, updated a symbolic link in `/srv/chatapp/test/current`, restarted the test service with `systemd`, and seeded the database. We managed three service instances; `test`, `blue`, and `green`,through templated `systemd` units and per-environment variables.

We automated DAST in two parts. A `Playwright` stage logged into `Keycloak`, generated authentication cookies, and stored them as artifacts. `OWASP ZAP` then consumed these cookies and performed a baseline passive scan, producing HTML and JSON reports. Finally, the deploy stage selected the appropriate color (`blue` or `green`) using a `Python` script on the `App VM`, started the correct service, and reconfigured `Nginx` on the `DMZ VM` via a templated reload script to route traffic to the new version.

By the end, we merged all stages into one unified `.gitlab-ci.yml` pipeline covering security scanning, testing, analysis, building, DAST, and blue/green deployment. This gave us a complete DevSecOps workflow that automatically validated, secured, and deployed each commit with minimal downtime and consistent quality.