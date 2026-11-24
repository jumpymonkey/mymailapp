"""Upstream Gmail v1 API models and strict internal view models."""

from pydantic import BaseModel, ConfigDict, Field


class GmailProfileResponse(BaseModel):
    """Response from GET /gmail/v1/users/me/profile."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    emailAddress: str
    messagesTotal: int = 0
    threadsTotal: int = 0


class GmailThreadListItem(BaseModel):
    """Lightweight thread entry returned by users.threads.list."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    snippet: str = ""
    historyId: str | None = None


class GmailThreadListResponse(BaseModel):
    """Paginated response from GET /gmail/v1/users/me/threads."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    threads: tuple[GmailThreadListItem, ...] = ()
    nextPageToken: str | None = None
    resultSizeEstimate: int = 0


class GmailHeader(BaseModel):
    """RFC 2822 header name/value pair."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    name: str
    value: str = ""


class GmailMessagePartBody(BaseModel):
    """Body payload or attachment pointer inside a MIME part."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    attachmentId: str | None = None
    size: int = 0
    data: str | None = None


class GmailMessagePart(BaseModel):
    """Recursive MIME part tree node."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    partId: str = ""
    mimeType: str = "text/plain"
    filename: str = ""
    headers: tuple[GmailHeader, ...] = ()
    body: GmailMessagePartBody = Field(default_factory=GmailMessagePartBody)
    parts: tuple["GmailMessagePart", ...] = ()


GmailMessagePart.model_rebuild()


class GmailMessage(BaseModel):
    """Single Gmail message resource within a thread."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    threadId: str = ""
    snippet: str = ""
    internalDate: str | None = None
    payload: GmailMessagePart | None = None


class GmailThread(BaseModel):
    """Full or metadata-hydrated Gmail thread resource."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    snippet: str = ""
    messages: tuple[GmailMessage, ...] = ()


class GmailAttachmentResponse(BaseModel):
    """Response from GET /gmail/v1/users/me/messages/{m}/attachments/{a}."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    size: int = 0
    data: str


class AttachmentView(BaseModel):
    """Strict view model for downloadable message attachments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attachment_id: str
    message_id: str
    filename: str
    mime_type: str
    size_bytes: int
    human_size: str


class ParsedMessageView(BaseModel):
    """Strict view model for a single rendered message inside a thread."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message_id: str
    sender: str
    recipients: str
    subject: str
    date_display: str
    snippet: str
    sanitized_srcdoc: str
    has_blocked_remote_images: bool
    attachments: tuple[AttachmentView, ...]


class ThreadSummaryView(BaseModel):
    """Strict view model for a search result row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: str
    subject: str
    participants: str
    date_display: str
    message_count: int
    snippet: str


class SearchResultsView(BaseModel):
    """Strict view model for paginated inbox search results."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    query: str
    threads: tuple[ThreadSummaryView, ...]
    next_page_token: str | None = None
    result_size_estimate: int = 0


class ThreadDetailView(BaseModel):
    """Strict view model for a full conversation thread."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    thread_id: str
    subject: str
    messages: tuple[ParsedMessageView, ...]
    remote_images_loaded: bool
