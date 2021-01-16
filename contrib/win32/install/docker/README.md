# Windows OpenSSH - Build using a Docker Container

## Create Docker images

Two separate Docker images are provided

* `Dockerfile-build`: A Dockerfile to create a Docker image with Visual Studio Build Tools 2017 with all required components to build OpenSSH

* `Dockerfile-openssh`: A Dockerfile which creates a pre-configured build environment for OpenSSH based on the aforementioned Docker image which contains the Visual Studio Build Tools 2017

### Visual Studio Build Image

To create the Docker image which contains all required Visual Studio Components to build OpenSSH use the following command:

```powershell
$ cd docker
$ docker build -f .\Dockerfile-build -t vs-build:ltsc2019 .
```

### OpenSSH build image

The following command will create a new Docker image configured to build OpenSSH for windows, based on the Visual Studio build image

```powershell
$ cd docker
$ docker build -f .\Dockerfile-openssh -t openssh-build:ltsc2019 .
```

The base image reference can be specified by the `FROM_IMAGE` build argument using the command line option `--build-arg`.
Default value: `vs-build:ltsc2019`

```powershell
$ docker build -f .\Dockerfile-openssh --build-arg FROM_IMAGE=nventive/build-agent:vs16.6.2 -t openssh-build:v16.6.2 .
```

The OpenSSH build image supports the following arguments and environment variables to configure the build process:

| Name              | Default Value                                  | Description                                                                  | Valid values                                                                                                                                                 |
|-------------------|------------------------------------------------|------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| REPO_URL          | https://github.com/PowerShell/openssh-portable | The URL of the Git repository of OpenSSH for Windows                         | Every valid Git Repository Url                                                                                                                               |
| REPO_DIRECTORY    | openssh-portable                               | To which directory Git shall clone the<br>repository in the Docker Container | Valid directory name                                                                                                                                         |
| BUILD_BRANCH      | latestw_all                                    | The branch to build                                                          | Existing branch name in Git Repository                                                                                                                       |
| BUILD_TAG         | head                                           | What Tag to build                                                            | Existing tag in Git Repository or the <br>following floating labels<br>head: latest commit in selected branch<br>latest: newest tag found in selected branch |
| PLATFORM          | x64                                            | The platform to build                                                        | x64, x86                                                                                                                                                     |
| CONFIGURATION     | Release                                        | The configuration to build                                                   | Release, Debug                                                                                                                                               |
| InstallDirectory  | `C:\${REPO_DIRECTORY}\contrib\win32\install` | The directory which contains this repository                                 | Valid directory name                                                                                                                                         |
| BinariesDirectory | `C:\Projects\openssh-dist`                     | Base directory of the created binaries<br>and MSI files                      | Valid directory name                                                                                                                                         |
| BuildMsi          | true                                           | Flag indicating if a MSI should be build                                     | true, false, 0, yes, no, 1                                                                                                                                   |
| BuildOpenSSH      | true                                           | Flag indicating if a OpenSSH should be build                                 | true, false, 0, yes, no, 1                                                                                                                                   |

Every argument value (ARG) is copied as default value to the corresponding environment variable with the same name.
By specifying deviating values for the environment variables at container startup the build process can be customized
after the docker images has been build.

## Build OpenSSH

To build OpenSSH with all default values

```powershell
$ docker run -ti --rm -m 4GB -v C:\Projects:c:\Projects openssh-build:ltsc2019
```

To build OpenSSH debug version for the x64 platform

```powershell
$ docker run -ti --rm -m 4GB -v C:\Projects:c:\Projects -e CONFIGURATION=Debug openssh-build:ltsc2019
```

To build OpenSSH for x64 and x86 platform

```powershell
$ docker run -ti --rm -m 4GB -v C:\Projects:c:\Projects -e Platform=x86,x64 openssh-build:ltsc2019
```

To build OpenSSH debug version for the x64 platform without a MSI file

```powershell
$ docker run -ti --rm -m 4GB -v C:\Projects:c:\Projects -e CONFIGURATION=Debug -e BuildMSI=false openssh-build:ltsc2019
```
