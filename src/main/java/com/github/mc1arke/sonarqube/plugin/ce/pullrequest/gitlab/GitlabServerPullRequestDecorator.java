/*
 * Copyright (C) 2020-2021 Markus Heberling, Michael Clarke
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.AnalysisDetails;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.DecorationResult;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.PostAnalysisIssueVisitor;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.PullRequestBuildStatusDecorator;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Commit;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.DiffRefs;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Discussion;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.MergeRequest;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Note;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.Position;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response.User;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.markup.MarkdownFormatterFactory;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.sonar.api.ce.posttask.QualityGate;
import org.sonar.api.issue.Issue;
import org.sonar.api.platform.Server;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.ce.task.projectanalysis.scm.Changeset;
import org.sonar.ce.task.projectanalysis.scm.ScmInfoRepository;
import org.sonar.db.alm.setting.ALM;
import org.sonar.db.alm.setting.AlmSettingDto;
import org.sonar.db.alm.setting.ProjectAlmSettingDto;
import org.sonarqube.ws.Common.Severity;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class GitlabServerPullRequestDecorator implements PullRequestBuildStatusDecorator {

    public static final String PULLREQUEST_GITLAB_INSTANCE_URL =
            "sonar.pullrequest.gitlab.instanceUrl";
    public static final String PULLREQUEST_GITLAB_PROJECT_ID =
            "sonar.pullrequest.gitlab.projectId";
    public static final String PULLREQUEST_GITLAB_PROJECT_URL =
            "sonar.pullrequest.gitlab.projectUrl";
    public static final String PULLREQUEST_GITLAB_PIPELINE_ID =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.gitlab.pipelineId";
    public static final String PULLREQUEST_COMMENTS_MIN_SEVERITY =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.gitlab.minSeverityComments";
    public static final String PULLREQUEST_CAN_FAIL_PIPELINE_ENABLED = 
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.gitlab.canFailPipeline";
    public static final String PULL_REQUEST_COMPACT_COMMENTS_ENABLED = 
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.comments.compact";
	public static final String PULL_REQUEST_COMMENT_SUMMARY_ENABLED =
			"com.github.mc1arke.sonarqube.plugin.branch.pullrequest.comment.summary.enabled";
	public static final String PULL_REQUEST_FILE_COMMENT_ENABLED =
			"com.github.mc1arke.sonarqube.plugin.branch.pullrequest.file.comment.enabled";
	public static final String PULL_REQUEST_DELETE_COMMENTS_ENABLED = 
			"com.github.mc1arke.sonarqube.plugin.branch.pullrequest.delete.comments.enabled";

    private static final Logger LOGGER = Loggers.get(GitlabServerPullRequestDecorator.class);
    private static final List<String> OPEN_ISSUE_STATUSES =
            Issue.STATUSES.stream().filter(s -> !Issue.STATUS_CLOSED.equals(s) && !Issue.STATUS_RESOLVED.equals(s))
                    .collect(Collectors.toList());

    private final Server server;
    private final ScmInfoRepository scmInfoRepository;

    public GitlabServerPullRequestDecorator(Server server, ScmInfoRepository scmInfoRepository) {
        super();
        this.server = server;
        this.scmInfoRepository = scmInfoRepository;
    }

    @Override
    public DecorationResult decorateQualityGateStatus(AnalysisDetails analysis, AlmSettingDto almSettingDto,
                                          ProjectAlmSettingDto projectAlmSettingDto) {
        LOGGER.info("starting to analyze with " + analysis.toString());
        String revision = analysis.getCommitSha();

        try {
            final String apiUrl = Optional.ofNullable(StringUtils.stripToNull(almSettingDto.getUrl()))
                    .orElseGet(() -> analysis.getScannerProperty(PULLREQUEST_GITLAB_INSTANCE_URL)
                            .orElseThrow(() -> new IllegalStateException(String.format(
                                    "Could not decorate Gitlab merge request. '%s' has not been set in scanner properties",
                                    PULLREQUEST_GITLAB_INSTANCE_URL))));
            final String projectId = Optional.ofNullable(StringUtils.stripToNull(projectAlmSettingDto.getAlmRepo()))
                    .orElseGet(() -> analysis.getScannerProperty(PULLREQUEST_GITLAB_PROJECT_ID)
                            .orElseThrow(() -> new IllegalStateException(String.format(
                                    "Could not decorate Gitlab merge request. '%s' has not been set in scanner properties",
                                    PULLREQUEST_GITLAB_PROJECT_ID))));
            final String pullRequestId = analysis.getBranchName();

            final String projectUrl = apiUrl + String.format("/projects/%s", URLEncoder.encode(projectId, StandardCharsets.UTF_8.name()));
            final String mergeRequestUrl = projectUrl + String.format("/merge_requests/%s", pullRequestId);

            final Map<String, String> headers = getHeaders(almSettingDto);

            final MergeRequest mergeRequest = getMergeRequest(headers, mergeRequestUrl);

            final String sourceProjectUrl = apiUrl + String.format("/projects/%d", mergeRequest.getSourceProjectId());
            final String statusUrl = sourceProjectUrl + String.format("/statuses/%s", revision);

            final String commitsUrl = mergeRequestUrl + "/commits";
            final String discussionsUrl = mergeRequestUrl + "/discussions";

            final String prHtmlUrl = analysis.getScannerProperty(PULLREQUEST_GITLAB_PROJECT_URL).map(url -> String.format("%s/merge_requests/%s", url, pullRequestId)).orElse(null);
            final boolean deleteCommentsEnabled = Boolean.parseBoolean(analysis.getScannerProperty(PULL_REQUEST_DELETE_COMMENTS_ENABLED).orElse("true"));

            LOGGER.info(String.format("Status url is: %s ", statusUrl));
            LOGGER.info(String.format("PR commits url is: %s ", commitsUrl));
            LOGGER.info(String.format("MR discussion url is: %s ", discussionsUrl));

            final List<Discussion> discussions = getOwnDiscussions(headers, discussionsUrl, apiUrl);

            Note summaryComment = null;
            Map<String, Note> lineComments = new HashMap<>();
            for (Discussion discussion : discussions) {
                for (Note note : discussion.getNotes()) {
                    Position position = note.getPosition();
                    if ("DiffNote".equals(note.getType()) && position!=null && position.getNewLine()!=null && position.getNewLine().trim().length() > 0) {
                        lineComments.put(position.getNewLine(), note);    
                    } else if ("DiscussionNote".equals(note.getType())) {
                        if (summaryComment==null) {
                            summaryComment = note;
                        } else if (note.getUpdatedAt()==null || note.getUpdatedAt().before(summaryComment.getUpdatedAt())) {
                            if (deleteCommentsEnabled) {
                                deleteCommitDiscussionNote(getNoteUrl(discussionsUrl, discussion.getId(), note.getId()), headers);
                            }
                        } else {
                            summaryComment = note;
                            if (deleteCommentsEnabled) {
                                deleteCommitDiscussionNote(getNoteUrl(discussionsUrl, discussion.getId(), summaryComment.getId()), headers);
                            }
                        }
                        
                    } else if (deleteCommentsEnabled) {
                        deleteCommitDiscussionNote(getNoteUrl(discussionsUrl, discussion.getId(), note.getId()), headers);
                    }
                }
            }

            doPipeline(analysis, headers, statusUrl);
            doSummary(analysis, headers, discussionsUrl, summaryComment);
            doFileComments(analysis, mergeRequest, headers, commitsUrl, discussionsUrl, lineComments);
            if (deleteCommentsEnabled) {
                for( Note note: lineComments.values()) {
                    deleteCommitDiscussionNote(getNoteUrl(discussionsUrl, note.getDiscussionId(), note.getId()), headers);
                }
            }
            
            return DecorationResult.builder().withPullRequestUrl(prHtmlUrl).build();
        } catch (IOException ex) {
            throw new IllegalStateException("Could not decorate Pull Request on Gitlab Server", ex);
        }

    }

    @Override
    public List<ALM> alm() {
        return Collections.singletonList(ALM.GITLAB);
    }

    private void doFileComments(AnalysisDetails analysis, MergeRequest mergeRequest, Map<String, String> headers,
            final String commitsUrl, final String discussionsUrl, Map<String, Note> lineNotes) throws IOException {
        final boolean fileCommentEnabled = Boolean.parseBoolean(analysis.getScannerProperty(PULL_REQUEST_FILE_COMMENT_ENABLED).orElse("true"));
        final Severity minSeverity = analysis.getScannerProperty(PULLREQUEST_COMMENTS_MIN_SEVERITY).map(Severity::valueOf).orElse(Severity.MAJOR);
        final boolean compactCommentsEnabled = Boolean.parseBoolean(analysis.getScannerProperty(PULL_REQUEST_COMPACT_COMMENTS_ENABLED).orElse("true"));
		if (fileCommentEnabled) {
            DiffRefs diffRefs = mergeRequest.getDiffRefs();
	        List<String> commits = getCommits(headers, commitsUrl);
	        List<PostAnalysisIssueVisitor.ComponentIssue> openIssues = analysis.getPostAnalysisIssueVisitor().getIssues().stream().filter(i -> OPEN_ISSUE_STATUSES.contains(i.getIssue().getStatus())).collect(Collectors.toList());
	        for (PostAnalysisIssueVisitor.ComponentIssue issue : openIssues) {
	            String path = analysis.getSCMPathForIssue(issue).orElse(null);
	            if (path != null && issue.getIssue().getLine() != null && isPrinted(issue.getIssue().severity(), minSeverity)) {
	                //only if we have a path and line number
	                String fileComment = analysis.createAnalysisIssueSummary(issue, new MarkdownFormatterFactory(), compactCommentsEnabled);
	
	                if (scmInfoRepository.getScmInfo(issue.getComponent())
	                        .filter(i -> i.hasChangesetForLine(issue.getIssue().getLine()))
	                        .map(i -> i.getChangesetForLine(issue.getIssue().getLine()))
	                        .map(Changeset::getRevision)
	                        .filter(commits::contains)
	                        .isPresent()) {
	                    //only if the change is on a commit, that belongs to this MR
						String lineNr = String.valueOf(issue.getIssue().getLine());
						Note existingNote = lineNotes.get(lineNr);
						if (existingNote!=null) {
			                try {
			                    updateCommitComment(discussionsUrl,  existingNote.getDiscussionId(), existingNote.getId(), headers, fileComment);							
			                } catch (IOException ex) {
			                	LOGGER.error("Can't update issue comment on line '{}' to '{}'.", issue.getIssue().getLine(), discussionsUrl);
			                }
		                    lineNotes.remove(lineNr);
						} else {

							List<NameValuePair> fileContentParams = Arrays.asList(
		                            new BasicNameValuePair("body", fileComment),
		                            new BasicNameValuePair("position[base_sha]", diffRefs.getBaseSha()),
		                            new BasicNameValuePair("position[start_sha]", diffRefs.getStartSha()),
		                            new BasicNameValuePair("position[head_sha]", diffRefs.getHeadSha()),
		                            new BasicNameValuePair("position[old_path]", path),
		                            new BasicNameValuePair("position[new_path]", path),
		                            new BasicNameValuePair("position[new_line]", lineNr),
		                            new BasicNameValuePair("position[position_type]", "text"));
							try {
									postCommitComment(discussionsUrl, headers, fileContentParams);
						    } catch (IOException ex) {
						    	LOGGER.error("Can't post issue comment on line '{}' to '{}'.", issue.getIssue().getLine(), discussionsUrl);
						    }
						}
	                } else {
	                    LOGGER.info(String.format("Skipping %s:%d since the commit does not belong to the MR", path, issue.getIssue().getLine()));
	                }
	            }
	        }
		}
    }

    private void doSummary(AnalysisDetails analysis, Map<String, String> headers, final String discussionsUrl, Note summaryComment) throws IOException {
        final boolean summaryCommentEnabled = Boolean.parseBoolean(analysis.getScannerProperty(PULL_REQUEST_COMMENT_SUMMARY_ENABLED).orElse("true"));
		if (summaryCommentEnabled) {
		    String summaryCommentBody = analysis.createAnalysisSummary(new MarkdownFormatterFactory());
		    if (summaryComment!=null) {
                try {
                    updateCommitComment(discussionsUrl,  summaryComment.getDiscussionId(), summaryComment.getId(), headers, summaryCommentBody);							
                } catch (IOException ex) {
                	LOGGER.error("Can't update summary comment to '{}'.", discussionsUrl);
                }
		    } else {
			    List<NameValuePair> summaryContentParams = Collections.singletonList(new BasicNameValuePair("body", summaryCommentBody));
			    try {
			        postCommitComment(discussionsUrl, headers, summaryContentParams);
			    } catch (IOException ex) {
			    	LOGGER.error("Can't post summary comment to '{}'.", discussionsUrl);
			    }
		    }
		    boolean approved = analysis.getQualityGateStatus() == QualityGate.Status.OK;
		    if (approved) {
		    	// TODO resolve by post to /merge_requests/1114/discussions/c4bbff952a9d3f5250f432e9cfeaf24bfe9ebb2a/resolve 
		    }
		}
	}

    private void doPipeline(AnalysisDetails analysis, Map<String, String> headers, final String statusUrl) throws IOException {
        final boolean canFailPipeline =  Boolean.parseBoolean(analysis.getScannerProperty(PULLREQUEST_CAN_FAIL_PIPELINE_ENABLED).orElse("true"));
        BigDecimal coverageValue = analysis.getCoverage().orElse(null);
        postStatus(new StringBuilder(statusUrl), headers, analysis, coverageValue, canFailPipeline);
    }
    
	private List<Discussion> getOwnDiscussions(Map<String, String> headers, final String discussionsUrl, String apiUrl)
			throws IOException {
		User user = getUser(headers, apiUrl);
		List<Discussion> discussions = getPagedList(discussionsUrl, headers, new TypeReference<List<Discussion>>() {});
		List<Discussion> result = new ArrayList<>();
		for(Discussion discussion: discussions) {
			if (discussion.getNotes()!=null && discussion.getNotes().size()>0) {
				Note firstNote = discussion.getNotes().get(0);
				if (!firstNote.isSystem() 
						&& firstNote.getAuthor() != null && firstNote.getAuthor().getUsername().equals(user.getUsername())
						&& ("DiffNote".equals(firstNote.getType()) || "DiscussionNote".equals(firstNote.getType()))) {
					firstNote.setDiscussionId(discussion.getId());
					result.add(discussion);
				}
			}
		}
		LOGGER.info(String.format("Discussions in MR: %s ", discussions
		        .stream()
		        .map(Discussion::getId)
		        .collect(Collectors.joining(", "))));
		return result;
	}
	
	private MergeRequest getMergeRequest(Map<String, String> headers, final String mergeRequestUrl) throws IOException {
		return getSingle(mergeRequestUrl, headers, MergeRequest.class);
	}
	
	private List<String> getCommits(Map<String, String> headers, final String commitsUrl) throws IOException {
		return getPagedList(commitsUrl, headers, new TypeReference<List<Commit>>() {}).stream().map(Commit::getId).collect(Collectors.toList());
	}
	
	private User getUser(Map<String, String> headers, final String apiURL) throws IOException {
		final String userURL = apiURL + "/user";
		LOGGER.info(String.format("User url is: %s ", userURL));
		User user = getSingle(userURL, headers, User.class);
		LOGGER.info(String.format("Using user: %s ", user.getUsername()));
		return user;
	}

    private <X> X getSingle(String url, Map<String, String> headers, Class<X> type) throws IOException {
        HttpGet httpGet = new HttpGet(url);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpGet.addHeader(entry.getKey(), entry.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            HttpResponse httpResponse = httpClient.execute(httpGet);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 200) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8));
                throw new IllegalStateException(
                        "An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                HttpEntity entity = httpResponse.getEntity();
                X result = new ObjectMapper()
                    .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, true)
                    .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .readValue(IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8), type);

                LOGGER.info(type + " received");

                return result;
            } else {
                throw new IOException("No response reveived");
            }
        }
    }

    private <X> List<X> getPagedList(String url, Map<String, String> headers,
                                     TypeReference<List<X>> type) throws IOException {
        HttpGet httpGet = new HttpGet(url);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpGet.addHeader(entry.getKey(), entry.getValue());
        }

        List<X> result = new ArrayList<>();

        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            HttpResponse httpResponse = httpClient.execute(httpGet);
            if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != 200) {
                LOGGER.error(httpResponse.toString());
                LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8));
                throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
            } else if (null != httpResponse) {
                LOGGER.debug(httpResponse.toString());
                HttpEntity entity = httpResponse.getEntity();
                List<X> pagedResults = new ObjectMapper()
                        .configure(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT, true)
                        .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                        .readValue(IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8), type);
                result.addAll(pagedResults);
                 Optional<String> nextURL = getNextUrl(httpResponse);
                if (nextURL.isPresent()) {
                    LOGGER.info("Getting next page");
                    result.addAll(getPagedList(nextURL.get(), headers, type));
                }
                LOGGER.info(type + " received");
            }
        }
        return result;
    }

    private void deleteCommitDiscussionNote(String discussionUrl, Map<String, String> headers) throws IOException {
        //https://docs.gitlab.com/ee/api/discussions.html#delete-a-commit-thread-note
        HttpDelete httpDelete = new HttpDelete(discussionUrl);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpDelete.addHeader(entry.getKey(), entry.getValue());
        }

        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            LOGGER.info("Deleting {} with headers {}", discussionUrl, headers);

            HttpResponse httpResponse = httpClient.execute(httpDelete);
            validateGitlabResponse(httpResponse, 204, "Commit discussions note deleted");
        } catch (IOException ex) {
        	LOGGER.error("Can't delete note '{}'", discussionUrl);
        }
    }

    private void postCommitComment(String commitCommentUrl, Map<String, String> headers, List<NameValuePair> params) throws IOException {
        //https://docs.gitlab.com/ee/api/commits.html#post-comment-to-commit
        HttpPost httpPost = new HttpPost(commitCommentUrl);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpPost.addHeader(entry.getKey(), entry.getValue());
        }
        httpPost.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

        LOGGER.info("Posting {} with headers {} to {}", params, headers, commitCommentUrl);

        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            HttpResponse httpResponse = httpClient.execute(httpPost);
            validateGitlabResponse(httpResponse, 201, "Comment posted");
        }
    }
    
    private void updateCommitComment(String commitCommentUrl, String discussionId, long noteId, Map<String, String> headers, String body) throws IOException {
        //https://docs.gitlab.com/ee/api/notes.html#modify-existing-merge-request-note
        String commitCommentModificationUrl = commitCommentUrl + "/" + discussionId + "/notes/" + noteId;

        HttpPut httpPut = new HttpPut(commitCommentModificationUrl);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpPut.addHeader(entry.getKey(), entry.getValue());
        }
        httpPut.setEntity(new UrlEncodedFormEntity(Collections.singletonList(new BasicNameValuePair("body", body))));
        LOGGER.info("Posting {} with headers {} to {}", body, headers, commitCommentModificationUrl);

        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            HttpResponse httpResponse = httpClient.execute(httpPut);
            validateGitlabResponse(httpResponse, 200, "Comment posted");
        }
        
    }

    private void postStatus(StringBuilder statusPostUrl, Map<String, String> headers, AnalysisDetails analysis,
                            BigDecimal coverage, boolean canFailPipeline) throws IOException {
        //See https://docs.gitlab.com/ee/api/commits.html#post-the-build-status-to-a-commit
        statusPostUrl.append("?name=SonarQube");
        String status = (!canFailPipeline || analysis.getQualityGateStatus() == QualityGate.Status.OK ? "success" : "failed");
        statusPostUrl.append("&state=").append(status);
        statusPostUrl.append("&target_url=").append(URLEncoder.encode(String.format("%s/dashboard?id=%s&pullRequest=%s", server.getPublicRootUrl(),
                URLEncoder.encode(analysis.getAnalysisProjectKey(),
                        StandardCharsets.UTF_8.name()), URLEncoder
                        .encode(analysis.getBranchName(),
                                StandardCharsets.UTF_8.name())), StandardCharsets.UTF_8.name()));
        statusPostUrl.append("&description=").append(URLEncoder.encode("SonarQube Status", StandardCharsets.UTF_8.name()));
        if (coverage != null) {
            statusPostUrl.append("&coverage=").append(coverage.toString());
        }
        analysis.getScannerProperty(PULLREQUEST_GITLAB_PIPELINE_ID).ifPresent(pipelineId -> statusPostUrl.append("&pipeline_id=").append(pipelineId));

        HttpPost httpPost = new HttpPost(statusPostUrl.toString());
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            httpPost.addHeader(entry.getKey(), entry.getValue());
        }

        try (CloseableHttpClient httpClient = HttpClients.createSystem()) {
            HttpResponse httpResponse = httpClient.execute(httpPost);
            if (null != httpResponse && httpResponse.toString().contains("Cannot transition status")) {
                // Workaround for https://gitlab.com/gitlab-org/gitlab-ce/issues/25807
                LOGGER.debug("Transition status is already {}", status);
            } else {
                validateGitlabResponse(httpResponse, 201, "Comment posted");
            }
        }
    }
	
    private void validateGitlabResponse(HttpResponse httpResponse, int expectedStatus, String successLogMessage) throws IOException {
        if (null != httpResponse && httpResponse.getStatusLine().getStatusCode() != expectedStatus) {
            LOGGER.error(httpResponse.toString());
            LOGGER.error(EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8));
            throw new IllegalStateException("An error was returned in the response from the Gitlab API. See the previous log messages for details");
        } else if (null != httpResponse) {
            LOGGER.debug(httpResponse.toString());
            LOGGER.info(successLogMessage);
        }
    }

    private static Optional<String> getNextUrl(HttpResponse httpResponse) {
        Header linkHeader = httpResponse.getFirstHeader("Link");
        if (linkHeader != null) {
            Matcher matcher = Pattern.compile("<([^>]+)>;[\\s]*rel=\"([a-z]+)\"").matcher(linkHeader.getValue());
            while (matcher.find()) {
                if (matcher.group(2).equals("next")) {
                    //found the next rel return the URL
                    return Optional.of(matcher.group(1));
                }
            }
        }
        return Optional.empty();
    }
    
	private Map<String, String> getHeaders(AlmSettingDto almSettingDto) {
		final String apiToken = almSettingDto.getPersonalAccessToken();
		Map<String, String> headers = new HashMap<>();
		headers.put("PRIVATE-TOKEN", apiToken);
		headers.put("Accept", "application/json");
		return headers;
	}
    
    protected boolean isPrinted(String severity, Severity minSeverity) {
        if (StringUtils.isBlank(severity)) {
            return true;
        }
        return Severity.valueOf(severity).getNumber() >= minSeverity.getNumber();
    }

	private String getNoteUrl(final String discussionsUrl, String discussionId, long noteId) {
		return discussionsUrl + String.format("/%s/notes/%d", discussionId,  noteId);
	}
    
}
