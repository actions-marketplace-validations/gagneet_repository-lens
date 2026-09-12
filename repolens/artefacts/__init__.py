"""Generated-artefact hygiene: regenerate after a merge, never text-merge a derived file.

  regenerate      map changed paths to the generators that rebuild them, and run them
  install-hooks   register the `generated` merge driver and the post-merge hooks (per clone)
  verify          .gitattributes and the regeneration rules must name the same files

Which files are generated, and by what, is named in `[artefacts]` in repolens.toml.
"""
