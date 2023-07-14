# Technical Assessment

## Sections

- [[I] Terraform and AWS](#terraform-and-aws)
- [[II] Linux, Ansible, and FluentD](#linx-ansible---and-fluentd)
- [[III] Docker](#docker)

---

# Terraform and AWS

Directory structure:

```
tree terraform/
├── data.tf
├── main.tf
├── outputs.tf
├── provider.tf
├── user_data
│   └── nginx.tpl
└── variables.tf
```

## Additional settings

To perform the task a remote backend was used which is described below. However, the result can also be replicated locally. 

To do this you need to specify the values for the following environment variables:

```
export AWS_ACCESS_KEY_ID="string"
export AWS_SECRET_ACCESS_KEY="another-string"
```

And also a Terraform variable __aws_key_pair_public_key__. In it, you need to specify the value of the public key that will be used to access the instance via SSH.
```
export TF_VAR_aws_key_pair_public_key="ssh-rsa AAAAB-long-string-example== o.bandrivsky@inc4.net"
```

## Implementation

If the values of variables in the variables.tf file are empty, the following local parameters will be used.
```
locals {
  instance_name    = "single-assessment"
  root_volume_size = 20
  instance_type    = "t2.micro"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
```

To specify the value for _Ubuntu ami_ using the following data source.

```
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

```

In the default VPC a security group is created with open ports [22, 80, 443].

```
module "assessment_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.9.0"

  name   = "assessment-sg"
  vpc_id = data.aws_vpc.default.id

  egress_rules        = ["all-all"]
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "https-443-tcp", "ssh-tcp"]
}
```

To install Nginx, the user_data mechanism is used with the following content.
```
#!/bin/bash
sudo apt update -y &&
sudo apt install -y nginx
echo "Hello, bloxroute!" > /var/www/html/index.html
```

Additionally, monitoring is enabled, the instance root volume size is set, and tags are specified.

To obtain information about the IP address of the future server, let's display it.
```
output "ec2_public_ip" {
  value = module.ec2_instance.public_ip
}
```

Finally:
```
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.2.1"

  name = var.ec2_name == "" || var.ec2_name == null ? local.instance_name : var.ec2_name

  instance_type = var.ec2_type == "" || var.ec2_type == null ? local.instance_type : var.ec2_type
  ami           = data.aws_ami.ubuntu.id
  key_name      = aws_key_pair.ssh_access.key_name
  monitoring    = true

  vpc_security_group_ids = [
    module.assessment_security_group.security_group_id
  ]

  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      volume_size = var.ec2_volume_size == null ? local.root_volume_size : var.ec2_volume_size
    },
  ]
  user_data = file("./user_data/nginx.tpl")
  tags      = local.tags
}
```

## Extra credit

To accomplish this task, a remote backend in the form of __Terraform Cloud__ was used.

Some advantages of using Terraform Cloud as a remote backend over a local backend while maintaining state:

    => Centralized State Management
    => State Locking and Consistency
    => Remote Operations and Collaboration
    => Automated Backups and Versioning
    => Integration and Extensibility
    => Scalability and High Availability
    => Access and Permissions Management
    => Greater Stability and Security

While a local backend can be suitable for small-scale projects or individual use, Terraform Cloud offers enhanced collaboration, centralized management, and additional features that streamline the workflow, especially in team environments or larger projects.

So in this case, you need to create/log in to Terraform Cloud and create a new workspace. Then, connect your GitHub repository. Here's an example:

![img-1](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img1.png)

Also need to fill in the variables section.

![img-2](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img2.png)

When changes are made to the repository, Terraform plan is triggered.

![img-3](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img3.png)

And apply the changes:

![img-4](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img4.png)


We have the IP address, and we can check the availability of nginx, for example, using curl.
```
curl 18.196.176.118
Hello, bloxroute!
```

Now, from localhost, connecting to the server using the previously provided SSH key.

![img-5](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img5.png)

---

# Linux, Ansible, and FluentD

Directory structure:

```
tree ansible/
├── ansible.cfg
├── hosts.yml
├── main.yml
└── roles
    ├── fluentd
    │   ├── defaults
    │   │   └── main.yml
    │   ├── handlers
    │   │   └── main.yml
    │   ├── tasks
    │   │   └── main.yml
    │   └── templates
    │       └── td-agent.conf.j2
    ├── logrotate
    │   ├── defaults
    │   │   └── main.yml
    │   ├── tasks
    │   │   └── main.yml
    │   └── templates
    │       └── logrotate.j2
    ├── nginx
    │   ├── defaults
    │   │   └── main.yml
    │   ├── handlers
    │   │   └── main.yml
    │   ├── tasks
    │   │   └── main.yml
    │   └── templates
    │       ├── index.j2
    │       └── site1.conf.j2
    └── ufw
        └── tasks
            └── main.yml

17 directories, 16 files
```

## Additional settings

To start working with the playbook needs to define a list of servers and the method of accessing them. 

Example: __hosts.yml__
```
[ec2]
ec2_eu_1   ansible_host=3.71.6.196 ansible_user=ubuntu ansible_ssh_private_key_file=../access-key.pem

```

## Implementation

### => Nginx

Check the presence of Nginx, add server configuration (__site1.conf.j2__) with HTML page (__index.j2__) and then restart it.

<details><summary>nginx/tasks/main.yml</summary>

```
---
- name: Setup nginx
  apt: 
    name: nginx 
    update_cache: yes 
    state: latest

- name: Start nginx
  service:
      name: nginx
      state: started
      enabled: yes

- name: Create site directory
  file:
    path: /var/www/{{ domain }}
    state: directory
    mode: '0775'
    owner: "{{ ansible_user }}"
    group: "{{ ansible_user }}"

- name: Remove nginx default site
  file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  notify: reload nginx

- name: Generate nginx.conf
  template:
    src: site1.conf.j2
    dest: /etc/nginx/sites-enabled/{{ domain }}
    owner: root
    group: root
    mode: '0644'
  notify: reload nginx

- name: Generate index.html
  template:
    src: index.j2
    dest: /var/www/{{ domain }}/index.html
    mode: '0775'
    owner: "{{ ansible_user }}"
    group: "{{ ansible_user }}"
  notify: reload nginx

```
</details>

"Hello, World!" is passed through a variable in the defaults and can be modified.

Additionally, the status of the Nginx response is checked after each restart.

```
- name: Nginx health check
  listen: nginx health check
  uri:
    url: 'http://{{ ansible_host }}'
    timeout: 1
  register: health_check_nginx
  retries: 10
  delay: 1
  until: health_check_nginx.status == 200

```
### => UFW

UFW is installed, and a policy is set to reject all except for ports 22 and 80 (which are in limited access mode).

<details><summary>ufw/tasks/main.yml</summary>

```
---
- name: Install UFW firewall
  apt: 
    name: ufw 
    update_cache: yes 
    state: latest  

- name: Allow ports with rate limiting
  ufw: 
    rule: limit
    port: '{{ item.number }}'
    proto: tcp
  with_items:
    - { number: 22, type: ssh }
    - { number: 80, type: http }
   
- name: Set firewall default policy
  ufw: 
    state: enabled 
    policy: reject
  become: true
```
</details>

### => logrotate

The presence of logrotate is checked, and the following configurations are applied for Nginx logs:
```
---
- name: Install logrotate
  package:
    name: logrotate
    state: present
  when: logrotate_scripts is defined and logrotate_scripts|length > 0

- name: Setup logrotate.d scripts
  template:
    src: logrotate.j2
    dest: "{{ logrotate_conf_dir }}{{ item.name }}"
  with_items: "{{ logrotate_scripts }}"
  when: logrotate_scripts is defined
```

```
logrotate_scripts: 
  - name: nginx-logs
    path: /var/log/nginx/*.log
    options:
      - daily
      - size 25M
      - rotate 7
      - compress
      - maxage 5
      - notifempty
      - delaycompress
      - create 0755 www-data adm
```

- Rotate logs daily.
- Rotate logs when they reach a size of 25MB.
- Keep up to 7 rotated log files.
- Compress the rotated log files.
- Remove logs older than 5 days.
- Only rotate logs if they are not empty.
- Delay compression of the rotated log files.
- Create new log files with the permissions 0755, owned by the "www-data" user and "adm" group.

### => Fluentd

Installation and generation of the configuration file:

<details><summary>fluentd/tasks/main.yml</summary>

```
---
- name: Setup dependencies
  apt:
    name:
      - apt-transport-https
      - gnupg2
    state: present

- name: Get td-agent apt_key
  apt_key:
    url: https://packages.treasuredata.com/GPG-KEY-td-agent
    state: present

- name: Get td-agent repository
  apt_repository:
    repo: >-
      deb
      http://packages.treasuredata.com/{{ fluentd_version }}/{{ ansible_distribution | lower }}/{{ ansible_distribution_release | lower }}/
      {{ ansible_distribution_release | lower }} contrib
    state: present
    update_cache: true

- name: Install td-agent
  package:
    name: td-agent
    state: "{{ fluentd_package_state }}"

- name: Generate td-agent.conf
  template:
    src: td-agent.conf.j2
    dest: /etc/td-agent/td-agent.conf
    owner: root
    group: root
    mode: 0644
  notify: Restart fluentd

- name: Determine fluent-gem executable location
  set_fact:
    fluent_gem_executable: /opt/td-agent/embedded/bin/fluent-gem
  when: fluentd_version < 4

- name: Determine fluent-gem executable location
  set_fact:
    fluent_gem_executable: /opt/td-agent/bin/fluent-gem
  when: fluentd_version >= 4

- name: Ensure Fluentd plugins are installed.
  gem:
    name: "{{ item.name | default(item) }}"
    executable: "{{ fluent_gem_executable }}"
    state: "{{ item.state | default('present') }}"
    version: "{{ item.version | default(omit) }}"
    user_install: false
  with_items: "{{ fluentd_plugins }}"

- name: Start Fluentd
  service:
    name: "{{ fluentd_service_name }}"
    state: "{{ fluentd_service_state }}"
    enabled: "{{ fluentd_service_enabled }}"

```
</details>

Fluentd Template
<details><summary>fluentd/templates/td-agent.conf.j2</summary>

```
####
## Source descriptions:
##

<source>
  @type tail
  path /var/log/nginx/access.log
  pos_file /var/log/td-agent/nginx-access.log.pos
  tag nginx.access
  <parse>
    @type nginx
  </parse>
</source>

<source>
  @type tail
  path /var/log/nginx/error.log
  pos_file /var/log/td-agent/nginx-error.log.pos
  tag nginx.error
  <parse>
    @type nginx
  </parse>
</source>

####
## Filter descriptions:
##

####
## Match descriptions:
##

<match nginx.access>
  @type file
  path /tmp/fluent/access/access.log
</match>

<match nginx.error>
  @type file
  path /tmp/fluent/error/error.log
</match>
```
</details>

Final main.yml file with role inclusions:
```
---
- name: Setup ec2 instance
  hosts: ec2
  become: true
  roles:
    - nginx
    - ufw
    - logrotate
    - fluentd
```

ansible run and curl check:

![img-6](https://github.com/OlehBandrivskyi/technical_assessment/blob/e8a889bcad4cd1e586df068f52d3d7deaf0a4a33/img/img6.png)
![img-7](https://github.com/OlehBandrivskyi/technical_assessment/blob/e8a889bcad4cd1e586df068f52d3d7deaf0a4a33/img/img7.png)