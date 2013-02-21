package Sandbox;

use strict;

use File::Spec;
use Cwd;
use Data::Dumper;
use File::Find;
use JSON;
use URI::Escape;
use Net::Netrc;
use Text::Wrap;

our $Project       = $ENV{JIRA_PROJECT};
our $JiraHost      = $ENV{JIRA_HOST};
our $Debug         = $ENV{DEBUG};
our $JiraApiUri    = "https://$JiraHost/rest/api/latest";
our $MaxLockWait   = 120;
our $DisplayWidth  = 80;

our $Editor = $ENV{EDITOR} || 'vi';

# not for external use
sub _root_path {
    my @path = File::Spec->splitdir(Cwd::getcwd);

    while (@path) {
        return @path if -d File::Spec->catdir(@path, '.git');
        pop @path;
    }

    die "Error: could not determine the sandbox root from the current path.\n\nThe current path does not appear to be a subtree of a sandbox.\nTry changing into a sandbox directory first and then running this command.";
}

# return the name of the sandbox directory
sub name {
    my ($self) = @_;
    my @path = $self->_root_path;
    return pop @path;
}

# return the sandbox's root directory, or a subdirectory relative to that as
# specified by the arguments - e.g. Sandbox->root('multiply', 'pages.ref')
sub root {
    my ($self, @path) = @_;
    return File::Spec->catdir($self->_root_path, @path);
}

# return the path to the project config file for this sandbox's copy of the
# specified project
sub project_config_path {
    my ($self, $project) = @_;

    my @found;
    my $name = $self->name;
    my $wanted = sub {
        push @found, $File::Find::name if /^\w+.${name}-${project}.conf$/
    };
    File::Find::find($wanted, "$ENV{HOME}/projects");

    die "Could not find project file for '$name-$project' in '$ENV{HOME}/projects'" unless @found == 1;
    return $found[0];
}

# return a hashref of values read from the project config file for this
# sandbox's copy of the specified project. additionally export it to the
# environmnet if $export is set
sub project_config {
    my ($self, $project, $export) = @_;

    my $path = $self->project_config_path($project);
    my $handle = IO::File->new($path);

    my $line;
    my $config;

    while (defined ($line = $handle->getline)) {
        chomp $line;
        my ($name, $value) = split /=/, $line, 2;
        $config->{$name} = $value;
    }

    if ($export) {
        $ENV{$_} = $config->{$-} for keys %$config;
    }

    return $config;
}

# utility function for executing system calls; it lets the user know what's going on and traps errors
sub print_and_run {
    my ($self, @args) = @_;
    my $command = join(' ', @args);
    print "> ".$command."\n" if $Debug;
    # for whatever reason, exec/system calls don't seem to work ... FIXME
    `$command`;
    die "Problem encountered running '$command'" if $?;
}

# collects a message from the user's $EDITOR environment variable
sub get_create_issue_message {
    my ($self, $message_type, $default) = @_;

    # setup the temporary message file
    my $temp_file = "/tmp/sb-create-issue-$$";
    system("echo -e '$default\n\n# Editing JIRA Issue $message_type. Lines starting with # will be ignored' > $temp_file");

    system("$Editor $temp_file");
    my $msg = `cat $temp_file`;
    chomp($msg);

    # remove lines beginning with #
    $msg =~ s/^#.*\n?//m;

    # right trim the string
    $msg =~ s/\s*$//;

    return $msg;
}

my $CreateIssueAllowedValues;
sub create_issue_allowed_values {
	my $self = shift;
	if (!$CreateIssueAllowedValues) {
		my $allowed_values_raw = Sandbox->jira_api_request("issue/createmeta?expand=projects.issuetypes.fields&projectKeys=$Project");

		@{$CreateIssueAllowedValues->{issue_types}} = map { $_->{name} } @{$allowed_values_raw->{projects}->[0]->{issuetypes}};
		my $fields = $allowed_values_raw->{projects}->[0]->{issuetypes}->[0]->{fields};
		@{$CreateIssueAllowedValues->{components}}  = map { $_->{name} } @{$fields->{components}->{allowedValues}};
		@{$CreateIssueAllowedValues->{priority}}    = map { $_->{name} } @{$fields->{priority}->{allowedValues}};
		@{$CreateIssueAllowedValues->{versions}}    = map { $_->{name} } @{$fields->{versions}->{allowedValues}};
		@{$CreateIssueAllowedValues->{fixVersions}} = map { $_->{name} } @{$fields->{fixVersions}->{allowedValues}};
	}
	return $CreateIssueAllowedValues;
}

sub issue_types {
	my $data = create_issue_allowed_values();
	return $data->{issue_types};
}

sub issue_components {
	my $data = create_issue_allowed_values();
	return $data->{components};
}

sub issue_priorities {
	my $data = create_issue_allowed_values();
	return $data->{priority};
}

sub issue_affects_versions {
	my $data = create_issue_allowed_values();
	return $data->{versions};
}

sub issue_fix_versions {
	my $data = create_issue_allowed_values();
	return $data->{fixVersions};
}

# create a issue in JIRA via XML RPC, returning the ID of the created issue
# see http://svn.atlassian.com/svn/public/contrib/jira/jira-rpc-samples/src/perl/createissue.pl
# see http://forums.atlassian.com/thread.jspa?forumID=46&threadID=10484
sub create_issue {
    my $self = shift;
    my $params = shift;

    my ($jira_user, $jira_password, $jira_account) = $self->netrc_credentials;

	# set up some reasonable defaults
    $params->{affects_version} ||= $self->production_release_id;
    $params->{fix_version}     ||= $self->current_release_id;
	$params->{issue_type}      ||= 'Bug';
	$params->{environment}     ||= 'Production';
	$params->{priority}        ||= 'Minor';
	$params->{description}     ||= $params->{subject};

	my $json = to_json(
		{ 
			fields => {
				issuetype   => { name   => $params->{issue_type}        },
				assignee    => { name   => $jira_user                   }, 
				project     => { key    => $Project                     },
				priority    => { name   => $params->{priority}          },
				reporter    => { name   => $jira_user                   },
				fixVersions => [ { name => $params->{fix_version}     } ],
				versions    => [ { name => $params->{affects_version} } ],
				description => $params->{description},
				summary     => $params->{summary},
				environment => $params->{environment},
				components  => $params->{component} ? [{ name => $params->{component} }] : [] #optional
			}
		}
	);

	my $tmp_data_file = "/tmp/sandbox-$$.json";
	open(JSON, ">$tmp_data_file");
	print JSON $json;
	close JSON;

	# build up our curl command for changing the issue status
    my $return_data_file = "/tmp/sandbox-error-$$.json";
	my $command = "curl -sw '%{http_code}' ";
	  $command .= "-u $jira_user:$jira_password ";
	  $command .= "-X POST ";
	  $command .= "--data \@$tmp_data_file ";
	  $command .= "-H 'Content-Type: application/json' ";
	  $command .= "-o $return_data_file ";
	  $command .= "'$JiraApiUri/issue'";

	# execute command; only a response of 204 indicates success.  die on all other failures
	my $return_code = `$command`;
	my $return_data = from_json(`cat $return_data_file`);
    unlink $return_data_file;

	die Dumper $return_data if $return_code != 201;
	return Sandbox->jira_issue($return_data->{key});
}

sub get_value_from_list {
	my ($class, $title, $list, $default) = @_;
	my $counter = 1;
	my $map = {};
    my $option_list = "$title\n";
	foreach my $option (@$list) {
		my $selected = $option eq $default ? '*' : ' ';
		$option_list .= "  $selected$counter) $option\n";
		$map->{$counter} = $option;
		$counter++;
	}
	print "$option_list>>";
	my $answer = <STDIN>;
	chomp $answer;
	$answer = $answer ? $map->{$answer} : $default;
	return $answer;
}

sub current_release_issues {
    my $self = shift;
    my $jql = 'fixversion = earliestUnreleasedVersion("' . $Project .'") and resolution = "fixed" order by resolutiondate asc';
    my $api_request = 'search?jql=' . uri_escape($jql) . '&maxResults=1000';
    my $issues = $self->jira_api_request($api_request);
    my @branches = map { $_->{key} } (@{$issues->{issues}});
    return wantarray ? @branches : \@branches;
}

sub netrc_credentials {
	my $self = shift;
	my $machine = Net::Netrc->lookup($JiraHost);
	return $machine->lpa;
}

sub jira_api_request {
    my ($self, $request) = @_;

    my ($jira_user, $jira_password, $jira_account) = $self->netrc_credentials;
    my $command = "curl -s -u $jira_user:$jira_password '$JiraApiUri/$request'";
    my $json = `$command`;
    die "Unable to connect to JIRA: $@" if $? or not $json;

    my $response;
    eval { $response = from_json($json) };
    die "Unable to evaluate response from JIRA server: not JSON.  >$json<" if not $response or $@;
    die @{$response->{errorMessages}} if $response->{errorMessages};

    return $response;
}

sub current_branch {
    my $current_branch = `git symbolic-ref HEAD`;
    chomp($current_branch);
    $current_branch =~ s/.*\///;
	return $current_branch;
}

sub issue_from_branch {
	my $current_branch = current_branch();
	$current_branch =~ s{-prod-hotfix$}{};
	return $current_branch;
}

sub issue_ready_for_qa {
	my ($self, $issue_id, $commits) = @_;

    # find the valid transition ids for this issue; we are looking for the one that 
	# matches resolving the issue.
	my $transitions_for_issue = $self->jira_api_request("issue/$issue_id/transitions");
	my $resolve_issue_id;
	foreach my $transition (@{$transitions_for_issue->{transitions}}) {
		if ($transition->{name} eq 'Resolve Issue') {
			$resolve_issue_id = $transition->{id};
			last;
		}
	}
    die "Issue $issue_id cannot be marked as resolved ; please see http://$JiraHost/browse/$issue_id" unless $resolve_issue_id;

    # build a single coherent message from the commit history for this issue
	my $comment = '';
	foreach my $commit (@$commits) {
		my ($id, $name, $date, $ref_names, $subject, $body) = split(/\|/, $commit);
		$subject =~ s{^$Project-\d+\: \[.*\]}{};   # auto generated commit message; redunant throw away
		$subject =~ s{^$Project-\d\:\s*}{};        # manually enterred into commit message; redunant throw away
		$comment .= "$id $name $date $subject\n";
	}
	my $json = to_json(
		{ 
			update => {
				comment => [ { add => { body => $comment } } ]
			},
			fields => {
				resolution => { name => 'Fixed' },
			},
			transition => { id => $resolve_issue_id },
		}
	);
	my $tmp_data_file = "/tmp/sandbox-$$.json";
	open(JSON, ">$tmp_data_file");
	print JSON $json;
	close JSON;

	# build up our curl command for changing the issue status
    my $tmp_error_file = "/tmp/sandbox-error-$$.json";
    my ($jira_user, $jira_password, $jira_account) = $self->netrc_credentials;
	my $command = "curl -sw '%{http_code}' ";
	  $command .= "-u $jira_user:$jira_password ";
	  $command .= "-X POST ";
	  $command .= "--data \@$tmp_data_file ";
	  $command .= "-H 'Content-Type: application/json' ";
	  $command .= "-o $tmp_error_file ";
	  $command .= "'$JiraApiUri/issue/$issue_id/transitions'";

	# execute command; only a response of 204 indicates success.  die on all other failures
	my $return_code = `$command`;

	if ($return_code ne '204') {
		my $json_error;
		open(JSON_ERROR, $tmp_error_file);
		while(<JSON_ERROR>) {
			$json_error .= $_;
		}
		close JSON_ERROR;
		unlink $tmp_data_file, $tmp_error_file;
		my $error = from_json($json_error);
		die Dumper $error;
	}

	# clean up and return
	unlink $tmp_data_file, $tmp_error_file;
	return;
}

sub currently_available_release_branches {
    my $self = shift;

    my $current_branch = $self->current_branch;

    $self->print_and_run('git','checkout','master');
    $self->print_and_run('git','pull');
    my @available = `git branch -a`;
    $self->print_and_run('git','checkout',$current_branch);

    chomp @available;
    my $available_branches = {};
    foreach my $branch (@available) {
		if ($branch =~ /($Project-\d+)$/) {
			$available_branches->{$1}++;
		}
    }

    # build actual list of branches that should be merged
    my @issues_in_jira = $self->current_release_issues;
    my @branches = ();
    my @no_branch_for_issue = ();
    foreach my $issue (@issues_in_jira) {
		if ($available_branches->{$issue}) {
			push @branches, $issue;
		}
		else {
			push @no_branch_for_issue, $issue;
		}
    }
    return \@branches, \@no_branch_for_issue;
}

our $ProjectData; # not doing strict OO here, so don't stuff information into $self
sub get_project {
    my $self = shift;
    $ProjectData = $self->jira_api_request("project/$Project") unless $ProjectData;
    return $ProjectData;
}

sub current_release_id {
    my $self = shift;
    my $project = $self->get_project;

    my $id;
    foreach my $version (@{$project->{versions}}) {
	next unless $version->{name} =~ m{^\S+$};
	if ($version->{released} eq 'false') {
			$id = $version->{name};
			last;
		}
    }
    return $id;
}

sub production_release_id {
    my $self = shift;
    my $project = $self->get_project;

    my $id;
    foreach my $version (@{$project->{versions}}) {
	next unless $version->{name} =~ m{^\S+$};
	if ($version->{released} eq 'false') {
			return $id;
		}
		$id = $version->{name};
    }
    return;
}

my $CloudFrontInfo;
sub cloudfront_http {
	load_cloudfront_info();
	return "http://$CloudFrontInfo->{CNAMEs}";
}

sub cloudfront_https {
	load_cloudfront_info();
	return "https://$CloudFrontInfo->{DomainName}";
}

sub cloudfront_bucket {
	load_cloudfront_info();
	return $CloudFrontInfo->{Origin};
}	

sub s3cmd {
	my $conf = -e "$ENV{HOME}/.s3cfg" ? "$ENV{HOME}/.s3cfg" : '/var/www/.s3cfg';
	return "s3cmd --config $conf";
}

sub load_cloudfront_info {
	my $s3cmd = s3cmd();
	return if $CloudFrontInfo;
	my @cflist = `$s3cmd cflist`;
	chomp @cflist;
	map { my ($name, $value) = m{^(.*?)\:\s+(.*)$}; $CloudFrontInfo->{$name} = $value } @cflist;
	my @cfinfo = `$s3cmd cfinfo $CloudFrontInfo->{DistId}`;
	chomp @cfinfo;
	map { my ($name, $value) = m{^(.*?)\:\s+(.*)$}; $CloudFrontInfo->{$name} = $value } @cfinfo;
}

sub is_issue_system_tracked_branch {
	my $class = shift;
	my $branch = shift || current_branch();
	return $branch =~ m{^$Project-\d+};
}

sub is_current_release {
	my $branch = shift || current_branch();
	my $production_release_id = production_release_id();
	return $branch eq $production_release_id;
}

sub is_not_current_release {
	return !is_current_release();
}

#-------------------------------------------------------------------------------
sub ascii_table {
#-------------------------------------------------------------------------------
# formats an array of array refs in a similar fashion to the output of a mysql
# terminal using the first row as the header.
#
	my $class = shift;
    my @table = @_;
    
    # determine the width of each cell in the output
    my @size = ();
    foreach my $row (@table) {
        my $counter;
        foreach my $element (@{$row}) {
            $size[$counter] = length($element) if length($element) > $size[$counter];
            $counter++;
        }
    }
    my @sep = map '-' x $_,@size;
    my $sep = '+-' . join('-+-',@sep) . '-+';
    my $table = "\n$sep\n";

    my $show_header;
    foreach my $row (@table) {
        my $counter;
        $table .= "|";
        foreach my $element (@{$row}) {
            $element = pack('A' . $size[$counter++], $element);
            $element =~ s/^([\-|\d|\.]+)(\s+)$/$2$1/;
            $table .= " $element |";
        }
        $table .= "\n";
        $table .= "$sep\n" if not $show_header++;
    }
    $table .= "$sep\n\n";

    return $table;
}

sub my_issues {
	my ($self) = shift;
    my $issue_data = $self->jira_api_request("search?jql=" . uri_escape("assignee = currentUser() AND resolution = Unresolved") , "&maxResults=1000");
	my @issues = map { Sandbox::JiraIssue->new($_) } @{$issue_data->{issues}};
	my @sorted_issues = sort {$a->priority_id <=> $b->priority_id } @issues;
	return wantarray ? @sorted_issues: \@sorted_issues;
}

sub jira_issue {
	my ($self, $issue_id) = @_;
    my $issue_data = Sandbox->jira_api_request("issue/$issue_id");
	$issue_data->{_id} = $issue_id;
	return Sandbox::JiraIssue->new($issue_data);
}

package Sandbox::JiraIssue;

use Data::Dumper;

sub new {
	my ($class, $data) = @_;
	my $self = $data;
	return bless $self, $class;
}

sub id {
	my $self = shift;
	return $self->{_id};
}

sub key {
	my $self = shift;
	return $self->{key};
}

sub status {
	my $self = shift;
	return $self->{fields}->{status}->{name};
}

sub priority {
	my $self = shift;
	return $self->{fields}->{priority}->{name};
}

sub priority_id {
	my $self = shift;
	return $self->{fields}->{priority}->{id};
}

sub assignee {
	my $self = shift;
	return $self->{fields}->{assignee}->{name};
}

sub resolution {
	my $self = shift;
	return $self->{fields}->{resolution}->{name};
}

sub summary {
	my $self = shift;
	return $self->{fields}->{summary};
}

sub description {
	my $self = shift;
	return $self->{fields}->{description};
}

# print out the description of the issue as sort of a sanity check for the developer
sub pretty {
	my $self = shift;
	my $pretty = '';
	$pretty .= "\n";
	$pretty .= "=" x $DisplayWidth . "\n";
	$pretty .= Text::Wrap::wrap('','', $self->id . ": " . $self->summary) . "\n";
	$pretty .= "-" x $DisplayWidth . "\n";
	$pretty .= Text::Wrap::wrap('    ','    ','Assigned to: ' . $self->assignee) . "\n";
	$pretty .= Text::Wrap::wrap('    ','    ','Status: ' . $self->status) . "\n";
	$pretty .= Text::Wrap::wrap('    ','    ','Resolution: ' . $self->resolution) . "\n";
	$pretty .= Text::Wrap::wrap('    ','    ',$self->description) . "\n";
	$pretty .= "=" x $DisplayWidth . "\n";
	return $pretty;
}



1;
