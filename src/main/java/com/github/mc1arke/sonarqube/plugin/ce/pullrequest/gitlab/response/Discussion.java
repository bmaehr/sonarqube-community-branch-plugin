/*
 * Copyright (C) 2019 Markus Heberling
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
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest.gitlab.response;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Discussion {
    private final String id;
    private final boolean individualNote;
    private final List<Note> notes;

    @JsonCreator
    public Discussion(
    		@JsonProperty("id") String id, 
    		@JsonProperty("individual_note") boolean individualNote,
    		@JsonProperty("notes") List<Note> notes) {
        this.id = id;
        this.individualNote = individualNote;
        this.notes = notes;
    }

    public String getId() {
        return id;
    }
    
    public boolean isIndividualNote() {
		return individualNote;
	}

	public List<Note> getNotes() {
        return notes;
    }
}
