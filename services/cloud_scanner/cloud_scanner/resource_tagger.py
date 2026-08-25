"""Spec-named re-export of the common resource tagger."""

from cloud_scanner.common.resource_tagger import ResourceTagger, extract_tags, tag_resources

__all__ = ["ResourceTagger", "extract_tags", "tag_resources"]
